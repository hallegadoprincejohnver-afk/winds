import test from 'node:test';
import assert from 'node:assert/strict';
import { clientRisk, decision, serverRisk } from '../src/risk.js';

function req(headers = {}) {
  return { get(name) { return headers[name.toLowerCase()] || headers[name] || ''; } };
}

test('provider proof is mandatory even for a clean-looking client', () => {
  const d = decision({
    providerVerified: false, bindingOk: true, replay: false, elapsedSeconds: 10, minSeconds: 2,
    server: { score: 0, reasons: [] }, client: { score: 0, reasons: [] }
  });
  assert.equal(d.allow, false);
  assert.equal(d.reason, 'provider_verification_failed');
});

test('replay is always blocked', () => {
  const d = decision({
    providerVerified: true, bindingOk: true, replay: true, elapsedSeconds: 10, minSeconds: 2,
    server: { score: 0, reasons: [] }, client: { score: 0, reasons: [] }
  });
  assert.equal(d.allow, false);
  assert.equal(d.reason, 'replay');
});

test('automation telemetry makes a completion high risk', () => {
  const c = clientRisk({ webdriver: true, events: [0, 0, 0, 0] });
  assert.ok(c.score >= 90);
  const d = decision({
    providerVerified: true, bindingOk: true, replay: false, elapsedSeconds: 10, minSeconds: 2,
    server: { score: 0, reasons: [] }, client: c
  });
  assert.equal(d.allow, false);
  assert.equal(d.reason, 'high_risk_client');
});

test('normal provider cross-site navigation is not penalized', () => {
  const r = serverRisk(req({
    'user-agent': 'Mozilla/5.0 Chrome/140.0',
    'sec-fetch-site': 'cross-site',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-dest': 'document'
  }));
  assert.equal(r.score, 0);
  assert.ok(r.reasons.includes('normal_cross_site_navigation'));
});

test('custom checkpoint minimum is enforced', () => {
  const d = decision({
    providerVerified: true, bindingOk: true, replay: false, elapsedSeconds: 2.5, minSeconds: 10,
    server: { score: 0, reasons: [] }, client: { score: 0, reasons: [] }
  });
  assert.equal(d.allow, false);
  assert.equal(d.reason, 'completion_too_fast');
});
