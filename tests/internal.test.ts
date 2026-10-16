import type { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ETH_ADDRESS, makeApp, resetDb, setupDb } from './helpers.js';

const SERVICE_KEY = 'service-key-service-key-123456';
let pool: Pool;
beforeAll(async () => {
  pool = await setupDb();
});
afterAll(async () => {
  await pool.end();
});
beforeEach(async () => {
  await resetDb(pool);
});

const check = (h: ReturnType<typeof makeApp>, q: { userId: string; address?: string; network?: string }, key: string | null = SERVICE_KEY) =>
  h.call('GET', `/internal/whitelist/allowed?userId=${q.userId}&network=${q.network ?? 'ethereum'}&address=${q.address ?? ETH_ADDRESS}`, { headers: key ? { 'x-service-key': key } : {} });

async function addressState(h: ReturnType<typeof makeApp>) {
  const s = await h.signIn();
  await h.call('POST', '/whitelist', { token: s.accessToken, body: { network: 'ethereum', address: ETH_ADDRESS } });
  return s;
}

describe('internal whitelist check', () => {
  it('does not exist unless a service key is configured', async () => {
    const h = makeApp(pool);
    const s = await h.signIn();
    const res = await check(h, { userId: s.userId });
    expect(res.status).toBe(404);
  });

  it('rejects a missing or wrong key', async () => {
    const h = makeApp(pool, { serviceApiKey: SERVICE_KEY });
    const s = await h.signIn();
    expect((await check(h, { userId: s.userId }, null)).status).toBe(401);
    expect((await check(h, { userId: s.userId }, 'wrong-key-wrong-key-wrong-key')).status).toBe(401);
  });

  it('is not usable with a user access token', async () => {
    const h = makeApp(pool, { serviceApiKey: SERVICE_KEY });
    const s = await h.signIn();
    const res = await h.call('GET', `/internal/whitelist/allowed?userId=${s.userId}&network=ethereum&address=${ETH_ADDRESS}`, { token: s.accessToken });
    expect(res.status).toBe(401);
  });

  it('says no until the address is confirmed and past its cooling-off, then yes, then no after removal', async () => {
    const h = makeApp(pool, { serviceApiKey: SERVICE_KEY });
    const s = await addressState(h);
    expect((await check(h, { userId: s.userId })).body).toEqual({ allowed: false }); // pending confirmation

    await h.call('POST', '/whitelist/confirm', { token: s.accessToken, body: { token: h.mailer.sent[0].token } });
    expect((await check(h, { userId: s.userId })).body).toEqual({ allowed: false }); // cooling down

    await pool.query(`UPDATE whitelist_addresses SET active_at = now() - interval '1 minute'`);
    expect((await check(h, { userId: s.userId })).body).toEqual({ allowed: true });
    expect((await check(h, { userId: s.userId, address: ETH_ADDRESS.toLowerCase() })).body).toEqual({ allowed: true }); // case does not matter

    const id = (await h.call('GET', '/whitelist', { token: s.accessToken })).body[0].id;
    await h.call('DELETE', `/whitelist/${id}`, { token: s.accessToken });
    expect((await check(h, { userId: s.userId })).body).toEqual({ allowed: false });
  });

  it('never mixes up users', async () => {
    const h = makeApp(pool, { serviceApiKey: SERVICE_KEY });
    const alice = await addressState(h);
    await h.call('POST', '/whitelist/confirm', { token: alice.accessToken, body: { token: h.mailer.sent[0].token } });
    await pool.query(`UPDATE whitelist_addresses SET active_at = now() - interval '1 minute'`);
    const bob = await h.signIn('bob@example.com');
    expect((await check(h, { userId: alice.userId })).body.allowed).toBe(true);
    expect((await check(h, { userId: bob.userId })).body.allowed).toBe(false);
  });

  it('validates its input', async () => {
    const h = makeApp(pool, { serviceApiKey: SERVICE_KEY });
    const s = await h.signIn();
    expect((await check(h, { userId: 'not-a-uuid' })).status).toBe(400);
    expect((await check(h, { userId: s.userId, network: 'dogecoin' })).status).toBe(400);
    expect((await check(h, { userId: s.userId, address: 'short' })).status).toBe(400);
  });

  it('is not slowed by the normal request limit, but wrong keys are limited', async () => {
    const h = makeApp(pool, { serviceApiKey: SERVICE_KEY, rateLimitPerMinute: 3 });
    const s = await h.signIn();
    for (let i = 0; i < 12; i++) expect((await check(h, { userId: s.userId })).status).toBe(200);
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await check(h, { userId: s.userId }, 'wrong-key-wrong-key-wrong-key')).status);
    expect(statuses).toContain(429);
  });
});
