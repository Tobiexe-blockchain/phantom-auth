import type { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { PASSWORD, makeApp, resetDb, setupDb } from './helpers.js';

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

describe('account lockout', () => {
  it('locks after repeated failures, even for the right password, then unlocks', async () => {
    const h = makeApp(pool);
    await h.register();
    for (let i = 0; i < 5; i++) expect((await h.login('alice@example.com', 'wrong wrong wrong')).status).toBe(401);

    const blocked = await h.login();
    expect(blocked.status).toBe(429);
    expect(blocked.body.error.code).toBe('ACCOUNT_LOCKED');
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);

    await pool.query(`UPDATE users SET locked_until = now() - interval '1 second'`);
    const ok = await h.login();
    expect(ok.status).toBe(200);
    expect((await pool.query('SELECT failed_attempts FROM users')).rows[0].failed_attempts).toBe(0);
  });

  it('counts failures atomically under parallel guessing', async () => {
    const h = makeApp(pool);
    await h.register();
    await Promise.all(Array.from({ length: 12 }, () => h.login('alice@example.com', 'wrong wrong wrong')));
    const row = (await pool.query('SELECT failed_attempts, locked_until FROM users')).rows[0];
    expect(row.failed_attempts).toBe(12);
    expect(row.locked_until).not.toBeNull();
    expect((await h.login()).status).toBe(429);
  });

  it('resets the counter after a successful login', async () => {
    const h = makeApp(pool);
    await h.register();
    for (let i = 0; i < 3; i++) await h.login('alice@example.com', 'wrong wrong wrong');
    expect((await h.login()).status).toBe(200);
    for (let i = 0; i < 4; i++) await h.login('alice@example.com', 'wrong wrong wrong');
    expect((await h.login()).status).toBe(200); // 4 failures after the reset is still under the limit
  });
});

describe('ip rate limits', () => {
  it('blocks an IP after too many failed logins across different accounts', async () => {
    const h = makeApp(pool, { ipFailedLoginMax: 3 });
    for (const name of ['a', 'b', 'c']) expect((await h.login(`${name}@example.com`, PASSWORD)).status).toBe(401);
    const blocked = await h.login('d@example.com', PASSWORD);
    expect(blocked.status).toBe(429);
    expect(blocked.body.error.code).toBe('RATE_LIMITED');
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('limits overall request rate per IP', async () => {
    const h = makeApp(pool, { rateLimitPerMinute: 5 });
    for (let i = 0; i < 5; i++) expect((await h.call('GET', '/auth/me')).status).toBe(401);
    expect((await h.call('GET', '/auth/me')).status).toBe(429);
    expect((await h.call('GET', '/health')).status).toBe(200); // health checks are exempt
  });

  it('uses separate budgets for separate IPs', async () => {
    const h = makeApp(pool, { ipFailedLoginMax: 2 });
    const from = (ip: string) => h.app.inject({ method: 'POST', url: '/auth/login', remoteAddress: ip, payload: { email: 'x@example.com', password: 'whatever' } });
    await from('10.0.0.1');
    await from('10.0.0.1');
    expect((await from('10.0.0.1')).statusCode).toBe(429);
    expect((await from('10.0.0.2')).statusCode).toBe(401);
  });
});
