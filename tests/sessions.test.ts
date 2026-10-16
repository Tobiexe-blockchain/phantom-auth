import type { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { makeApp, resetDb, setupDb } from './helpers.js';

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

describe('refresh token rotation', () => {
  it('issues a new pair and invalidates the old refresh token', async () => {
    const h = makeApp(pool);
    const s = await h.signIn();
    const next = await h.call('POST', '/auth/refresh', { body: { refreshToken: s.refreshToken } });
    expect(next.status).toBe(200);
    expect(next.body.refreshToken).not.toBe(s.refreshToken);
    expect((await h.call('GET', '/auth/me', { token: next.body.accessToken })).status).toBe(200);
  });

  it('stores only hashes of refresh tokens', async () => {
    const h = makeApp(pool);
    const s = await h.signIn();
    const stored = (await pool.query('SELECT token_hash FROM refresh_tokens')).rows.map((r) => r.token_hash);
    expect(stored).not.toContain(s.refreshToken);
    expect(stored[0]).toMatch(/^[0-9a-f]{64}$/);
  });

  it('detects reuse of a rotated token and ends the whole session family', async () => {
    const h = makeApp(pool);
    const s = await h.signIn();
    const first = await h.call('POST', '/auth/refresh', { body: { refreshToken: s.refreshToken } });

    const replay = await h.call('POST', '/auth/refresh', { body: { refreshToken: s.refreshToken } });
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe('REFRESH_TOKEN_REUSED');

    // The legitimate newest token is revoked too, because we cannot tell who holds the stolen one.
    const newest = await h.call('POST', '/auth/refresh', { body: { refreshToken: first.body.refreshToken } });
    expect(newest.status).toBe(401);

    const events = (await pool.query(`SELECT event FROM audit_log WHERE event = 'refresh_reuse_detected'`)).rowCount;
    expect(events).toBe(1);
  });

  it('lets only one of two simultaneous refreshes win', async () => {
    const h = makeApp(pool);
    const s = await h.signIn();
    const [a, b] = await Promise.all([
      h.call('POST', '/auth/refresh', { body: { refreshToken: s.refreshToken } }),
      h.call('POST', '/auth/refresh', { body: { refreshToken: s.refreshToken } }),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 401]);
    const winner = a.status === 200 ? a : b;
    expect((await h.call('POST', '/auth/refresh', { body: { refreshToken: winner.body.refreshToken } })).status).toBe(401);
  });

  it('keeps separate sessions (other devices) alive when one family is reused', async () => {
    const h = makeApp(pool);
    const phone = await h.signIn();
    const laptop = (await h.login()).body;
    await h.call('POST', '/auth/refresh', { body: { refreshToken: phone.refreshToken } });
    await h.call('POST', '/auth/refresh', { body: { refreshToken: phone.refreshToken } }); // reuse
    expect((await h.call('POST', '/auth/refresh', { body: { refreshToken: laptop.refreshToken } })).status).toBe(200);
  });

  it('rejects expired and unknown tokens', async () => {
    const h = makeApp(pool);
    const s = await h.signIn();
    await pool.query(`UPDATE refresh_tokens SET expires_at = now() - interval '1 minute'`);
    expect((await h.call('POST', '/auth/refresh', { body: { refreshToken: s.refreshToken } })).body.error.code).toBe('INVALID_REFRESH_TOKEN');
    expect((await h.call('POST', '/auth/refresh', { body: { refreshToken: 'x'.repeat(43) } })).status).toBe(401);
  });
});

describe('logout', () => {
  it('ends the session for that refresh token only', async () => {
    const h = makeApp(pool);
    const phone = await h.signIn();
    const laptop = (await h.login()).body;
    expect((await h.call('POST', '/auth/logout', { body: { refreshToken: phone.refreshToken } })).status).toBe(204);
    expect((await h.call('POST', '/auth/refresh', { body: { refreshToken: phone.refreshToken } })).status).toBe(401);
    expect((await h.call('POST', '/auth/refresh', { body: { refreshToken: laptop.refreshToken } })).status).toBe(200);
  });

  it('answers 204 for unknown tokens so it reveals nothing', async () => {
    const h = makeApp(pool);
    expect((await h.call('POST', '/auth/logout', { body: { refreshToken: 'y'.repeat(43) } })).status).toBe(204);
  });

  it('logout-all ends every session and kills access tokens that are still valid', async () => {
    const h = makeApp(pool);
    const a = await h.signIn();
    const b = (await h.login()).body;
    expect((await h.call('POST', '/auth/logout-all', { token: a.accessToken })).status).toBe(204);
    expect((await h.call('GET', '/auth/me', { token: a.accessToken })).status).toBe(401);
    expect((await h.call('GET', '/auth/me', { token: b.accessToken })).status).toBe(401);
    expect((await h.call('POST', '/auth/refresh', { body: { refreshToken: a.refreshToken } })).status).toBe(401);
    expect((await h.call('POST', '/auth/refresh', { body: { refreshToken: b.refreshToken } })).status).toBe(401);
    // A fresh login still works.
    expect((await h.login()).status).toBe(200);
  });
});
