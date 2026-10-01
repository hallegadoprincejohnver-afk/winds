import { createClient } from 'redis';

let redis = null;
const memory = new Map();

function sweep() {
  const now = Date.now();
  for (const [k, v] of memory) if (v.expiresAt <= now) memory.delete(k);
}

export async function initStore(url) {
  if (!url) return { type: 'memory' };
  redis = createClient({ url });
  redis.on('error', err => console.error('[redis]', err.message));
  await redis.connect();
  return { type: 'redis' };
}

export async function getJson(key) {
  if (redis) {
    const raw = await redis.get(key);
    return raw ? JSON.parse(raw) : null;
  }
  sweep();
  return memory.get(key)?.value ?? null;
}

export async function setJson(key, value, ttlSeconds) {
  if (redis) {
    await redis.set(key, JSON.stringify(value), { EX: ttlSeconds });
    return;
  }
  memory.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
}

export async function del(key) {
  if (redis) return redis.del(key);
  memory.delete(key);
}

export async function setOnce(key, value, ttlSeconds) {
  if (redis) {
    const result = await redis.set(key, JSON.stringify(value), { NX: true, EX: ttlSeconds });
    return result === 'OK';
  }
  sweep();
  if (memory.has(key)) return false;
  memory.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  return true;
}

export async function incrWithTtl(key, ttlSeconds) {
  if (redis) {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, ttlSeconds);
    return count;
  }
  sweep();
  const current = memory.get(key);
  const count = Number(current?.value || 0) + 1;
  memory.set(key, {
    value: count,
    expiresAt: current?.expiresAt || Date.now() + ttlSeconds * 1000
  });
  return count;
}

export async function atomicSetOnce(key, value, ttlSeconds) {
  return setOnce(key, value, ttlSeconds);
}
