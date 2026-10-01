import express from 'express';
import crypto from 'node:crypto';
import { initStore, getJson, setJson, del, setOnce, incrWithTtl } from './store.js';
import { randomToken, sha256, hmacSha256, safeEqual, buildClientBinding, requestIp, isLikelyBrowser } from './security.js';
import { serverRisk, clientRisk, decision } from './risk.js';
import { CLIENT_SCRIPT } from './client.js';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', Math.max(0, Number(process.env.TRUST_PROXY_HOPS || 1)));
app.use(express.json({ limit: '16kb', strict: true }));

const cfg = {
  integrationKey: process.env.INTEGRATION_KEY || '',
  sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  baseUrl: (process.env.PUBLIC_BASE_URL || '').replace(/\/$/, ''),
  linkvertiseToken: process.env.LINKVERTISE_ANTIBYPASS_TOKEN || '',
  lootSecret: process.env.LOOTLABS_POSTBACK_SECRET || '',
  ttl: Math.max(120, Number(process.env.SESSION_TTL_SECONDS || 900)),
  clearanceTtl: Math.max(15, Number(process.env.CLEARANCE_TTL_SECONDS || 45)),
  minSeconds: Math.max(1, Number(process.env.MIN_CHECKPOINT_SECONDS || 2)),
  bindIp: process.env.BIND_IP !== 'false',
  bindUa: process.env.BIND_USER_AGENT !== 'false',
  startLimit: Math.max(1, Number(process.env.RATE_LIMIT_START || 10)),
  callbackLimit: Math.max(1, Number(process.env.RATE_LIMIT_CALLBACK || 30)),
  clientLimit: Math.max(1, Number(process.env.RATE_LIMIT_CLIENT || 20)),
  tsSite: process.env.TURNSTILE_SITE_KEY || '',
  tsSecret: process.env.TURNSTILE_SECRET_KEY || '',
  tsHost: process.env.TURNSTILE_HOSTNAME || '',
  tsAction: process.env.TURNSTILE_ACTION || 'clear-checkpoint'
};
const tsEnabled = Boolean(cfg.tsSite && cfg.tsSecret);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  next();
});

function cookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) {
      try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch {}
    }
  }
  return out;
}
app.use((req, _res, next) => { req.cookies = cookies(req.get('cookie')); next(); });

function audit(event, req, extra = {}) {
  const b = buildClientBinding(req);
  console.log(JSON.stringify({
    event, at: new Date().toISOString(),
    ipHash: b.ipHash.slice(0, 16), uaHash: b.uaHash.slice(0, 16), ...extra
  }));
}

function auth(req, res, next) {
  const supplied = req.get('x-antibypass-key') || '';
  if (!cfg.integrationKey || !safeEqual(supplied, cfg.integrationKey)) {
    audit('integration_unauthorized', req);
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
  next();
}

async function limited(req, res, bucket, max, seconds) {
  const slot = Math.floor(Date.now() / (seconds * 1000));
  const key = 'ab:rl:' + bucket + ':' + sha256(requestIp(req)) + ':' + slot;
  const n = await incrWithTtl(key, seconds + 2);
  if (n > max) {
    res.setHeader('Retry-After', String(seconds));
    audit('rate_limited', req, { bucket });
    res.status(429).json({ ok: false, error: 'rate_limited' });
    return false;
  }
  return true;
}

function base(req) { return cfg.baseUrl || ('https://' + req.get('host')); }

function safeHttpsUrl(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:') return null;
    return u.toString();
  } catch { return null; }
}

function ticket(sid, scope) {
  const exp = Math.floor(Date.now() / 1000) + cfg.clearanceTtl;
  const payload = sid + '.' + scope + '.' + exp;
  return payload + '.' + hmacSha256(cfg.sessionSecret, payload);
}

function validTicket(raw, sid, scope) {
  const p = String(raw || '').split('.');
  if (p.length !== 4 || p[0] !== sid || p[1] !== scope || !/^\d+$/.test(p[2])) return false;
  if (Number(p[2]) < Math.floor(Date.now() / 1000)) return false;
  return safeEqual(p[3], hmacSha256(cfg.sessionSecret, p[0] + '.' + p[1] + '.' + p[2]));
}

function setSid(res, sid) {
  res.setHeader('Set-Cookie',
    '__Host-ab_sid=' + encodeURIComponent(sid) +
    '; Path=/; Max-Age=' + cfg.ttl +
    '; HttpOnly; Secure; SameSite=Lax');
}

function clearSid(res) {
  res.setHeader('Set-Cookie',
    '__Host-ab_sid=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
}

async function loadSession(req) {
  const sid = req.cookies['__Host-ab_sid'];
  if (!sid) return { sid: null, s: null, b: null, ok: false };
  const s = await getJson('ab:s:' + sid);
  if (!s) return { sid, s: null, b: null, ok: false };
  const b = buildClientBinding(req);
  const ipOk = !cfg.bindIp || (s.binding && safeEqual(s.binding.ipHash, b.ipHash));
  const uaOk = !cfg.bindUa || (s.binding && safeEqual(s.binding.uaHash, b.uaHash));
  return { sid, s, b, ok: Boolean(ipOk && uaOk) };
}

async function block(res, sid, s, reason, risk) {
  const blocked = Object.assign({}, s, { status: 'blocked', blockReason: reason, risk });
  await setJson('ab:s:' + sid, blocked, cfg.ttl);
  clearSid(res);
  return res.status(403).send('Verification failed');
}

async function verifyLinkvertise(hash) {
  if (!cfg.linkvertiseToken) return { ok: false, reason: 'linkvertise_token_not_configured' };
  if (!/^[a-fA-F0-9]{64}$/.test(hash)) return { ok: false, reason: 'invalid_hash' };
  try {
    const url =
      'https://publisher.linkvertise.com/api/v1/anti_bypassing?token=' +
      encodeURIComponent(cfg.linkvertiseToken) + '&hash=' + encodeURIComponent(hash);
    const r = await fetch(url, { method: 'POST', signal: AbortSignal.timeout(5000) });
    const raw = (await r.text()).trim();
    return { ok: raw === 'TRUE', raw };
  } catch (e) {
    return { ok: false, reason: 'linkvertise_verify_unavailable', detail: e && e.message };
  }
}

async function verifyTurnstile(req, token) {
  if (!tsEnabled) return true;
  if (!token || token.length > 4096) return false;
  try {
    const body = new URLSearchParams({ secret: cfg.tsSecret, response: token });
    const ip = requestIp(req);
    if (ip && ip !== 'unknown') body.set('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(5000)
    });
    const d = await r.json();
    if (!d.success) return false;
    if (cfg.tsAction && d.action && d.action !== cfg.tsAction) return false;
    if (cfg.tsHost && d.hostname && d.hostname !== cfg.tsHost) return false;
    return true;
  } catch { return false; }
}

async function waitLoot(clickId) {
  for (let i = 0; i < 5; i++) {
    const proof = await getJson('ab:lootclick:' + clickId);
    if (proof) return proof;
    if (i < 4) await new Promise(r => setTimeout(r, 250));
  }
  return null;
}

function redirectWithTicket(res, s, sid) {
  const sep = s.destinationUrl.includes('?') ? '&' : '?';
  return res.redirect(
    s.destinationUrl + sep +
    'ab_ticket=' + encodeURIComponent(ticket(sid, 'step' + s.step)) +
    '&step=' + s.step
  );
}

app.get('/healthz', (_req, res) =>
  res.json({ ok: true, service: 'clear-antibypass', version: '1.0.0', turnstile: tsEnabled })
);
app.get('/', (_req, res) => res.type('text').send('Clear Anti-Bypass Gateway'));

app.post('/v1/session/start', auth, async (req, res) => {
  if (!await limited(req, res, 'start', cfg.startLimit, 60)) return;
  const provider = String(req.body?.provider || '').toLowerCase();
  const providerUrl = safeHttpsUrl(req.body?.providerUrl);
  const destinationUrl = safeHttpsUrl(req.body?.destinationUrl);
  const step = Number(req.body?.step || 1);
  if (!['linkvertise', 'lootlabs'].includes(provider) ||
      !providerUrl || !destinationUrl || ![1, 2].includes(step)) {
    return res.status(400).json({ ok: false, error: 'invalid_session_parameters' });
  }
  const sid = randomToken(32);
  const s = {
    sid, provider, providerUrl, destinationUrl, step,
    flowId: String(req.body?.flowId || '').slice(0, 160),
    createdAt: Date.now(),
    minSeconds: Math.max(cfg.minSeconds, Number(req.body?.minSeconds || cfg.minSeconds)),
    binding: null, telemetry: null, status: 'pending',
    lootClickId: randomToken(18), turnstileVerified: false
  };
  await setJson('ab:s:' + sid, s, cfg.ttl);
  audit('session_started', req, { provider, step });
  res.json({
    ok: true, sessionId: sid,
    sessionUrl: base(req) + '/v1/go/' + encodeURIComponent(sid),
    lootlabsPuid: s.lootClickId,
    turnstileEnabled: tsEnabled
  });
});

app.get('/v1/go/:sid', async (req, res) => {
  const sid = req.params.sid;
  const s = await getJson('ab:s:' + sid);
  if (!s || s.status !== 'pending') return res.status(404).send('Session expired');
  if (!isLikelyBrowser(req)) {
    return block(res, sid, s, 'non_browser_client', { score: 100, reasons: ['non_browser_client'] });
  }
  const b = buildClientBinding(req);
  if (!s.binding) {
    s.binding = { ipHash: b.ipHash, uaHash: b.uaHash, softHash: b.softHash };
  } else if ((cfg.bindIp && !safeEqual(s.binding.ipHash, b.ipHash)) ||
             (cfg.bindUa && !safeEqual(s.binding.uaHash, b.uaHash))) {
    return block(res, sid, s, 'session_binding_mismatch', { score: 100, reasons: ['binding_mismatch'] });
  }
  await setJson('ab:s:' + sid, s, cfg.ttl);
  setSid(res, sid);

  const target = s.provider === 'lootlabs'
    ? (() => {
        const u = new URL(s.providerUrl);
        u.searchParams.set('puid', s.lootClickId);
        return u.toString();
      })()
    : s.providerUrl;

  const nonce = crypto.randomBytes(16).toString('base64url');
  if (!tsEnabled) {
    res.setHeader('Content-Security-Policy',
      "default-src 'none'; script-src 'nonce-" + nonce +
      "' 'self'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    return res.type('html').send(
      '<!doctype html><html><head><meta charset="utf-8"><meta name="ab-challenge" content="' +
      nonce + '"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking...</title></head>' +
      '<body><script nonce="' + nonce + '">' + CLIENT_SCRIPT +
      '\nsetTimeout(function(){location.replace(' + JSON.stringify(target) + ')},350);</script></body></html>'
    );
  }

  res.setHeader('Content-Security-Policy',
    "default-src 'none'; script-src 'nonce-" + nonce +
    "' 'self' https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  const next = JSON.stringify(target);
  return res.type('html').send(
    '<!doctype html><html><head><meta charset="utf-8"><meta name="ab-challenge" content="' + nonce +
    '"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking...</title>' +
    '<script nonce="' + nonce + '" src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"></script></head>' +
    '<body><div id="ts"></div><script nonce="' + nonce + '">' + CLIENT_SCRIPT +
    '\nvar next=' + next +
    ';async function done(token){var r=await fetch(\'/v1/client/turnstile\',{method:\'POST\',credentials:\'same-origin\',headers:{\'content-type\':\'application/json\'},body:JSON.stringify({token:token})});if(r.ok)location.replace(next);else document.body.textContent=\'Verification failed\';}' +
    'turnstile.ready(function(){turnstile.render(\'#ts\',{sitekey:' + JSON.stringify(cfg.tsSite) +
    ',appearance:\'interaction-only\',execution:\'render\',action:' + JSON.stringify(cfg.tsAction) +
    ',callback:done});});</script></body></html>'
  );
});

app.post('/v1/client/telemetry', async (req, res) => {
  if (!await limited(req, res, 'client', cfg.clientLimit, 30)) return;
  const x = await loadSession(req);
  if (!x.s || !x.ok) return res.status(403).json({ ok: false });
  x.s.telemetry = Object.assign({}, x.s.telemetry || {}, req.body || {}, { at: Date.now() });
  x.s.serverRisk = serverRisk(req);
  await setJson('ab:s:' + x.sid, x.s, cfg.ttl);
  res.json({ ok: true });
});
app.post('/v1/client/hello', async (req, res) => {
  if (!await limited(req, res, 'client', cfg.clientLimit, 30)) return;
  const x = await loadSession(req);
  if (!x.s || !x.ok) return res.status(403).json({ ok: false });
  x.s.telemetry = Object.assign({}, x.s.telemetry || {}, req.body || {}, { at: Date.now() });
  x.s.serverRisk = serverRisk(req);
  await setJson('ab:s:' + x.sid, x.s, cfg.ttl);
  res.json({ ok: true });
});
app.post('/v1/client/heartbeat', async (req, res) => {
  const x = await loadSession(req);
  if (!x.s || !x.ok) return res.status(403).json({ ok: false });
  if (!await limited(req, res, 'client', cfg.clientLimit, 30)) return;
  x.s.telemetry = Object.assign({}, x.s.telemetry || {}, req.body || {}, { at: Date.now() });
  x.s.serverRisk = serverRisk(req);
  await setJson('ab:s:' + x.sid, x.s, cfg.ttl);
  res.json({ ok: true });
});

app.post('/v1/client/turnstile', async (req, res) => {
  if (!tsEnabled) return res.status(404).json({ ok: false });
  if (!await limited(req, res, 'client', cfg.clientLimit, 30)) return;
  const x = await loadSession(req);
  if (!x.s || !x.ok) return res.status(403).json({ ok: false });
  if (!await verifyTurnstile(req, String(req.body?.token || ''))) {
    await block(res, x.sid, x.s, 'turnstile_failed', { score: 100, reasons: ['turnstile_failed'] });
    return;
  }
  x.s.turnstileVerified = true;
  x.s.turnstileAt = Date.now();
  await setJson('ab:s:' + x.sid, x.s, cfg.ttl);
  res.json({ ok: true });
});

app.get('/v1/relay/linkvertise', async (req, res) => {
  if (!await limited(req, res, 'callback', cfg.callbackLimit, 60)) return;

  const x = await loadSession(req);
  if (!x.s || !x.ok) return res.status(403).send('Verification failed');

  const s = x.s;
  const relay = String(req.query.relay || '');
  const stage = Number(req.query.stage || 0);

  if (
    s.provider !== 'linkvertise' ||
    s.status !== 'pending' ||
    !relay ||
    relay !== String(s.flowId || '') ||
    stage !== Number(s.step)
  ) {
    return block(res, x.sid, s, 'linkvertise_relay_mismatch', {
      score: 100,
      reasons: ['relay_session_mismatch']
    });
  }

  if (!isLikelyBrowser(req)) {
    return block(res, x.sid, s, 'non_browser_client', {
      score: 100,
      reasons: ['non_browser_client']
    });
  }

  if (!s.telemetry) {
    return block(res, x.sid, s, 'missing_client_integrity', {
      score: 100,
      reasons: ['missing_client_integrity']
    });
  }

  const server = serverRisk(req);
  const client = clientRisk(s.telemetry);
  const d = decision({
    providerVerified: true,
    bindingOk: x.ok,
    replay: false,
    elapsedSeconds: (Date.now() - s.createdAt) / 1000,
    minSeconds: s.minSeconds,
    server,
    client,
    turnstileOk: true
  });

  if (!d.allow) return block(res, x.sid, s, d.reason, d);

  const optionalHash = String(req.query.hash || '').trim();
  if (optionalHash && cfg.linkvertiseToken) {
    const pv = await verifyLinkvertise(optionalHash);
    if (!pv.ok) {
      return block(res, x.sid, s, 'linkvertise_provider_hash_rejected', {
        allow: false,
        reason: 'linkvertise_provider_hash_rejected',
        score: 100,
        reasons: ['linkvertise_provider_hash_rejected']
      });
    }
  }

  s.status = 'completed';
  s.providerEvidence = {
    gatewayRelay: true,
    providerHashPresent: Boolean(optionalHash),
    at: Date.now()
  };
  s.risk = d;

  await setJson('ab:s:' + x.sid, s, cfg.clearanceTtl);
  audit('linkvertise_gateway_verified', req, {
    sid: x.sid.slice(0, 12),
    step: s.step,
    score: d.score
  });

  return redirectWithTicket(res, s, x.sid);
});

app.get('/v1/provider/linkvertise/complete', async (req, res) => {
  if (!await limited(req, res, 'callback', cfg.callbackLimit, 60)) return;
  const x = await loadSession(req);
  if (!x.s || !x.ok) return res.status(403).send('Verification failed');
  const s = x.s;
  if (s.provider !== 'linkvertise' || s.status !== 'pending') return res.status(403).send('Verification failed');
  if (tsEnabled && !s.turnstileVerified) {
    return block(res, x.sid, s, 'turnstile_verification_required',
      { score: 100, reasons: ['turnstile_verification_required'] });
  }

  const hash = String(req.query.hash || '');
  const pv = await verifyLinkvertise(hash);
  const d = decision({
    providerVerified: pv.ok,
    bindingOk: x.ok,
    replay: false,
    elapsedSeconds: (Date.now() - s.createdAt) / 1000,
    minSeconds: s.minSeconds,
    server: serverRisk(req),
    client: clientRisk(s.telemetry || {}),
    turnstileOk: !tsEnabled || s.turnstileVerified
  });
  if (!d.allow) return block(res, x.sid, s, d.reason, d);

  if (!await setOnce('ab:lvproof:' + hash, { sid: x.sid, at: Date.now() }, 30)) {
    return block(res, x.sid, s, 'replay',
      { allow: false, reason: 'replay', score: 100, reasons: ['linkvertise_hash_replay'] });
  }

  s.status = 'completed';
  s.providerEvidence = { hash, verified: true, at: Date.now() };
  s.risk = d;
  await setJson('ab:s:' + x.sid, s, cfg.clearanceTtl);
  audit('linkvertise_verified', req, { sid: x.sid.slice(0, 12), step: s.step, score: d.score });
  return redirectWithTicket(res, s, x.sid);
});

app.get('/v1/webhooks/lootlabs', async (req, res) => {
  const secret = String(req.query.secret || '');
  if (!cfg.lootSecret || !safeEqual(secret, cfg.lootSecret)) return res.status(401).send('unauthorized');
  const clickId = String(req.query.click_id || '');
  const ip = String(req.query.ip || '');
  const uniqueId = String(req.query.unique_id || '');
  if (!clickId || !ip || !uniqueId) return res.status(400).send('missing');
  if (!await limited(req, res, 'loot-webhook', 60, 60)) return;
  if (!await setOnce('ab:lootproof:' + uniqueId, { clickId, ip, at: Date.now() }, 180)) {
    return res.status(409).send('duplicate');
  }
  await setJson('ab:lootclick:' + clickId, { clickId, ip, uniqueId, at: Date.now() }, 180);
  audit('lootlabs_postback', req, {
    clickIdHash: sha256(clickId).slice(0, 16),
    uniqueIdHash: sha256(uniqueId).slice(0, 16)
  });
  res.status(204).end();
});

app.get('/v1/provider/lootlabs/complete', async (req, res) => {
  if (!await limited(req, res, 'callback', cfg.callbackLimit, 60)) return;
  const x = await loadSession(req);
  if (!x.s || !x.ok) return res.status(403).send('Verification failed');
  const s = x.s;
  if (s.provider !== 'lootlabs' || s.status !== 'pending') return res.status(403).send('Verification failed');
  if (tsEnabled && !s.turnstileVerified) {
    return block(res, x.sid, s, 'turnstile_verification_required',
      { score: 100, reasons: ['turnstile_verification_required'] });
  }

  const p = await waitLoot(s.lootClickId);
  if (!p || p.clickId !== s.lootClickId || p.ip !== x.b.ip) {
    return block(res, x.sid, s, 'lootlabs_postback_mismatch',
      { allow: false, reason: 'lootlabs_postback_mismatch', score: 100, reasons: ['missing_or_mismatched_postback'] });
  }

  if (!await setOnce('ab:lootclaim:' + p.uniqueId, { sid: x.sid, at: Date.now() }, 180)) {
    return block(res, x.sid, s, 'replay',
      { allow: false, reason: 'replay', score: 100, reasons: ['lootlabs_unique_id_replay'] });
  }

  const d = decision({
    providerVerified: true,
    bindingOk: x.ok,
    replay: false,
    elapsedSeconds: (Date.now() - s.createdAt) / 1000,
    minSeconds: s.minSeconds,
    server: serverRisk(req),
    client: clientRisk(s.telemetry || {}),
    turnstileOk: !tsEnabled || s.turnstileVerified
  });
  if (!d.allow) return block(res, x.sid, s, d.reason, d);

  s.status = 'completed';
  s.providerEvidence = { clickId: s.lootClickId, uniqueId: p.uniqueId, ip: p.ip, at: Date.now() };
  s.risk = d;
  await setJson('ab:s:' + x.sid, s, cfg.clearanceTtl);
  audit('lootlabs_verified', req, { sid: x.sid.slice(0, 12), step: s.step, score: d.score });
  return redirectWithTicket(res, s, x.sid);
});

app.post('/v1/verify', auth, async (req, res) => {
  const sid = String(req.body?.sessionId || '');
  const step = Number(req.body?.step || 1);
  const raw = String(req.body?.ticket || '');
  if (!sid || ![1, 2].includes(step) || !validTicket(raw, sid, 'step' + step)) {
    return res.status(403).json({ ok: false, verified: false });
  }
  const s = await getJson('ab:s:' + sid);
  if (!s || s.status !== 'completed' || Number(s.step) !== step) {
    return res.status(403).json({ ok: false, verified: false });
  }
  await del('ab:s:' + sid);
  audit('clearance_claimed', req, { sid: sid.slice(0, 12), provider: s.provider, step });
  res.json({ ok: true, verified: true, provider: s.provider, step, flowId: s.flowId, risk: s.risk || null });
});

app.post('/v1/session/status', auth, async (req, res) => {
  const sid = String(req.body?.sessionId || '');
  const s = await getJson('ab:s:' + sid);
  if (!s) return res.status(404).json({ ok: false, status: 'expired' });
  res.json({
    ok: true,
    status: s.status,
    provider: s.provider,
    step: s.step,
    risk: s.risk || null,
    blockReason: s.blockReason || null
  });
});

app.use((_req, res) => res.status(404).json({ ok: false, error: 'not_found' }));

const port = Number(process.env.PORT || 10000);
await initStore(process.env.REDIS_URL);
app.listen(port, '0.0.0.0', () => {
  console.log('[antibypass] listening on ' + port + '; turnstile=' + tsEnabled + '; redis=' + Boolean(process.env.REDIS_URL));
});
