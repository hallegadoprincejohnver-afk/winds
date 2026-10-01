const AUTOMATION_RE = /(playwright|puppeteer|selenium|webdriver|headless|phantom|nightmare|electron|httpclient|curl|wget|python-requests|aiohttp)/i;
const BYPASS_HOST_RE = /(bypass\.vip|bypass\.city|rip\.linkvertise\.lol|izen\.lol|bypassunlock\.com|bypass\.tools|dead[-_ ]?square|live\.linkvertise\.lol)/i;

export function serverRisk(req) {
  let score = 0;
  const reasons = [];
  const ua = req.get('user-agent') || '';
  const referer = req.get('referer') || '';
  const host = (() => {
    try { return new URL(referer).hostname; } catch { return ''; }
  })();

  if (!ua) { score += 45; reasons.push('missing_ua'); }
  if (AUTOMATION_RE.test(ua)) { score += 80; reasons.push('automation_ua'); }
  if (BYPASS_HOST_RE.test(host)) { score += 100; reasons.push('known_bypass_referrer'); }

  const secFetchSite = req.get('sec-fetch-site');
  const secFetchMode = req.get('sec-fetch-mode');
  const secFetchDest = req.get('sec-fetch-dest');
  if (secFetchSite === 'cross-site' && secFetchDest === 'document' && secFetchMode === 'navigate') {
    reasons.push('normal_cross_site_navigation');
  }

  const xff = req.get('x-forwarded-for');
  if (xff && xff.split(',').length > 4) {
    score += 15;
    reasons.push('xff_anomaly');
  }

  return { score: Math.min(score, 100), reasons };
}

export function clientRisk(telemetry = {}) {
  let score = 0;
  const reasons = [];
  if (telemetry.webdriver === true || telemetry.webdriverGlobal === true) { score += 90; reasons.push('webdriver'); }
  if (telemetry.playwright === true || telemetry.puppeteer === true) { score += 90; reasons.push('automation_globals'); }
  if (telemetry.domTampered === true || telemetry.nativeReferenceChanged === true) { score += 70; reasons.push('dom_or_native_tamper'); }
  if (telemetry.nativeApiTampered === true) { score += 70; reasons.push('native_api_tamper'); }
  if (telemetry.visibilityHiddenTooOften === true) { score += 15; reasons.push('visibility_anomaly'); }
  if (telemetry.timingAnomaly === true) { score += 20; reasons.push('timing_anomaly'); }
  if (Array.isArray(telemetry.events) && telemetry.events.length === 0) { score += 10; reasons.push('no_interaction_telemetry'); }
  return { score: Math.min(score, 100), reasons };
}

export function decision({ providerVerified, bindingOk, replay, elapsedSeconds, server, client, turnstileOk = true }) {
  const reasons = [...server.reasons, ...client.reasons];
  if (replay) return { allow: false, reason: 'replay', score: 100, reasons };
  if (!bindingOk) return { allow: false, reason: 'session_binding_mismatch', score: 100, reasons };
  if (!providerVerified) return { allow: false, reason: 'provider_verification_failed', score: 100, reasons };
  if (!turnstileOk) return { allow: false, reason: 'turnstile_verification_required', score: 100, reasons };
  if (elapsedSeconds < 2) return { allow: false, reason: 'completion_too_fast', score: 100, reasons };
  const score = Math.min(100, server.score + client.score);
  if (score >= 85) return { allow: false, reason: 'high_risk_client', score, reasons };
  return { allow: true, reason: 'verified', score, reasons };
}
