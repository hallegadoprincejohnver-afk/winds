import test from 'node:test';
import assert from 'node:assert/strict';
import { randomToken, sha256, hmacSha256, safeEqual } from '../src/security.js';

test('randomToken is high entropy', () => {
  const a = randomToken();
  const b = randomToken();
  assert.notEqual(a, b);
  assert.ok(a.length >= 40);
});

test('sha256 is stable', () => assert.equal(sha256('x'), sha256('x')));

test('hmac constant-time comparison accepts only exact matching signatures', () => {
  const a = hmacSha256('secret', 'x');
  assert.equal(safeEqual(a, hmacSha256('secret', 'x')), true);
  assert.equal(safeEqual(a, hmacSha256('secret', 'y')), false);
});
