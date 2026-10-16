import jwt from 'jsonwebtoken';
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

describe('registration', () => {
  it('creates an account and stores an argon2id hash, never the password', async () => {
    const h = makeApp(pool);
    const res = await h.register();
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ email: 'alice@example.com' });
    const row = (await pool.query('SELECT password_hash FROM users')).rows[0];
    expect(row.password_hash.startsWith('$argon2id$')).toBe(true);
    expect(row.password_hash).not.toContain(PASSWORD);
  });

  it('treats emails case-insensitively and rejects duplicates', async () => {
    const h = makeApp(pool);
    await h.register('alice@example.com');
    const dup = await h.register('ALICE@Example.com');
    expect(dup.status).toBe(409);
    expect(dup.body.error.code).toBe('EMAIL_TAKEN');
  });

  it('rejects short passwords, bad emails, and extra fields', async () => {
    const h = makeApp(pool);
    expect((await h.register('a@example.com', 'short')).status).toBe(400);
    expect((await h.register('not-an-email', PASSWORD)).status).toBe(400);
    expect((await h.call('POST', '/auth/register', { body: { email: 'b@example.com', password: PASSWORD, isAdmin: true } })).status).toBe(400);
  });

  it('rejects a password that contains the email name', async () => {
    const h = makeApp(pool);
    const res = await h.register('jonathan@example.com', 'jonathan-is-my-name');
    expect(res.body.error.code).toBe('WEAK_PASSWORD');
  });
});

describe('login and access tokens', () => {
  it('returns tokens and lets the user read their profile', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const me = await h.call('GET', '/auth/me', { token: accessToken });
    expect(me.status).toBe(200);
    expect(me.body).toMatchObject({ email: 'alice@example.com', twoFactorEnabled: false });
  });

  it('gives the same answer for a wrong password and an unknown email', async () => {
    const h = makeApp(pool);
    await h.register();
    const wrong = await h.login('alice@example.com', 'definitely the wrong one');
    const unknown = await h.login('nobody@example.com', PASSWORD);
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body);
  });

  it('rejects missing, malformed, expired, wrongly signed, and unsigned tokens', async () => {
    const h = makeApp(pool);
    const { userId } = await h.signIn();
    const base = { subject: userId, issuer: h.config.issuer, audience: h.config.audience };
    const claims = { typ: 'access', tv: 0 };

    const expired = jwt.sign(claims, h.config.jwtSecret, { ...base, expiresIn: -10 });
    const wrongKey = jwt.sign(claims, 'another-secret-another-secret-another-1', { ...base, expiresIn: 60 });
    const wrongAudience = jwt.sign(claims, h.config.jwtSecret, { ...base, audience: 'someone-else', expiresIn: 60 });
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const unsigned = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ ...claims, sub: userId, iss: h.config.issuer, aud: h.config.audience, exp: 9999999999 })}.`;
    const hs512 = jwt.sign(claims, h.config.jwtSecret, { ...base, algorithm: 'HS512', expiresIn: 60 });

    for (const token of [undefined, 'garbage', expired, wrongKey, wrongAudience, unsigned, hs512]) {
      const res = await h.call('GET', '/auth/me', { token });
      expect(res.status, String(token).slice(0, 20)).toBe(401);
    }
  });

  it('does not accept an mfa token as an access token', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    await h.enableTwoFactor(accessToken);
    const login = await h.login();
    expect(login.body.mfaRequired).toBe(true);
    expect((await h.call('GET', '/auth/me', { token: login.body.mfaToken })).status).toBe(401);
  });
});

describe('http hardening', () => {
  it('sets security headers and returns JSON errors', async () => {
    const h = makeApp(pool);
    const res = await h.call('GET', '/nope');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('rejects oversized bodies', async () => {
    const h = makeApp(pool);
    const res = await h.call('POST', '/auth/login', { body: { email: 'a@example.com', password: 'x'.repeat(40_000) } });
    expect(res.status).toBe(413);
  });
});

describe('audit log', () => {
  it('records events and exposes only the caller\'s own', async () => {
    const h = makeApp(pool);
    const alice = await h.signIn('alice@example.com');
    await h.signIn('bob@example.com');
    await h.login('alice@example.com', 'wrong password here');

    const res = await h.call('GET', '/audit', { token: alice.accessToken });
    const events = res.body.map((e: any) => e.event);
    expect(events).toEqual(expect.arrayContaining(['register', 'login_success', 'login_failed']));

    const owners = new Set((await pool.query('SELECT user_id FROM audit_log WHERE user_id IS NOT NULL')).rows.map((r) => r.user_id));
    expect(owners.size).toBe(2); // both users have events in the table
    const mine = (await pool.query('SELECT count(*)::int AS n FROM audit_log WHERE user_id = $1', [alice.userId])).rows[0].n;
    expect(res.body).toHaveLength(mine); // but the endpoint returns only alice's
  });

  it('cannot be edited or deleted', async () => {
    const h = makeApp(pool);
    await h.register();
    await expect(pool.query(`UPDATE audit_log SET event = 'x'`)).rejects.toThrow(/append-only/);
    await expect(pool.query('DELETE FROM audit_log')).rejects.toThrow(/append-only/);
  });
});
