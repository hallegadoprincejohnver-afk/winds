import crypto from 'node:crypto';

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

export function hmacSha256(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

export function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

export function normalizeIp(raw) {
  let ip = String(raw || '').trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

export function requestIp(req) {
  return normalizeIp(req.ip || req.socket.remoteAddress || 'unknown');
}

export function buildClientBinding(req) {
  const ip = requestIp(req);
  const ua = req.get('user-agent') || '';
  const lang = req.get('accept-language') || '';
  const secChUa = req.get('sec-ch-ua') || '';
  const secChPlatform = req.get('sec-ch-ua-platform') || '';
  return {
    ip,
    ipHash: sha256(ip),
    uaHash: sha256(ua),
    softHash: sha256(ua + '\n' + lang + '\n' + secChUa + '\n' + secChPlatform)
  };
}

export function isLikelyBrowser(req) {
  const ua = req.get('user-agent') || '';
  if (!ua) return false;
  if (/curl|wget|python-requests|aiohttp|httpclient|go-http-client|java\/|libwww|powershell|postmanruntime/i.test(ua)) return false;
  return /mozilla\/5\.0|chrome\/|safari\/|firefox\/|edg\//i.test(ua);
}

export function sanitizeId(value, max = 160) {
  return String(value || '').replace(/[^A-Za-z0-9._:-]/g, '').slice(0, max);
}
