import type { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { currentCode } from '../src/totp.js';
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

const clearReplayGuard = () => pool.query('UPDATE users SET last_totp_step = NULL');

describe('two-factor setup', () => {
  it('returns a secret and a QR code, and is not active until verified', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const setup = await h.call('POST', '/auth/2fa/setup', { token: accessToken });
    expect(setup.status).toBe(200);
    expect(setup.body.otpauthUrl).toMatch(/^otpauth:\/\/totp\//);
    expect(setup.body.qrCodeDataUrl).toMatch(/^data:image\/png;base64,/);
    expect((await h.login()).body.mfaRequired).toBe(false);
  });

  it('stores the secret encrypted', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const setup = await h.call('POST', '/auth/2fa/setup', { token: accessToken });
    const stored = (await pool.query('SELECT totp_secret_enc FROM users')).rows[0].totp_secret_enc as string;
    expect(stored).not.toContain(setup.body.secret);
    expect(stored.split('.')).toHaveLength(3);
  });

  it('rejects a wrong code, and enables with a right one returning 10 backup codes', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    await h.call('POST', '/auth/2fa/setup', { token: accessToken });
    const bad = await h.call('POST', '/auth/2fa/enable', { token: accessToken, body: { code: '000000' } });
    expect(bad.status).toBe(401);

    const { backupCodes } = await h.enableTwoFactor(accessToken);
    expect(backupCodes).toHaveLength(10);
    expect(new Set(backupCodes).size).toBe(10);
    const stored = (await pool.query('SELECT code_hash FROM backup_codes')).rows.map((r) => r.code_hash);
    expect(stored.every((s: string) => s.startsWith('$argon2id$'))).toBe(true);
    expect((await h.call('GET', '/auth/me', { token: accessToken })).body.twoFactorEnabled).toBe(true);
  });

  it('cannot enable without starting setup', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const res = await h.call('POST', '/auth/2fa/enable', { token: accessToken, body: { code: '123456' } });
    expect(res.body.error.code).toBe('NO_PENDING_SETUP');
  });
});

describe('login with two-factor', () => {
  it('stops after the password and issues no session tokens until the code is right', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const { secret } = await h.enableTwoFactor(accessToken);

    const step1 = await h.login();
    expect(step1.status).toBe(200);
    expect(step1.body).toMatchObject({ mfaRequired: true });
    expect(step1.body.accessToken).toBeUndefined();
    expect(step1.body.refreshToken).toBeUndefined();

    const done = await h.call('POST', '/auth/login/2fa', { body: { mfaToken: step1.body.mfaToken, code: currentCode(secret, 1) } });
    expect(done.status).toBe(200);
    expect((await h.call('GET', '/auth/me', { token: done.body.accessToken })).status).toBe(200);
  });

  it('rejects a wrong code and counts it toward the lockout', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    await h.enableTwoFactor(accessToken);
    const { body } = await h.login();
    for (let i = 0; i < 5; i++) {
      const res = await h.call('POST', '/auth/login/2fa', { body: { mfaToken: body.mfaToken, code: '000000' } });
      expect(res.status).toBe(401);
    }
    const locked = await h.call('POST', '/auth/login/2fa', { body: { mfaToken: body.mfaToken, code: '000000' } });
    expect(locked.status).toBe(429);
  });

  it('accepts each code only once', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const { secret } = await h.enableTwoFactor(accessToken);
    const code = currentCode(secret, 1);
    const a = await h.login();
    expect((await h.call('POST', '/auth/login/2fa', { body: { mfaToken: a.body.mfaToken, code } })).status).toBe(200);
    const b = await h.login();
    const replay = await h.call('POST', '/auth/login/2fa', { body: { mfaToken: b.body.mfaToken, code } });
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe('INVALID_CODE');
  });

  it('lets a backup code work exactly once', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const { backupCodes } = await h.enableTwoFactor(accessToken);
    const first = await h.login();
    expect((await h.call('POST', '/auth/login/2fa', { body: { mfaToken: first.body.mfaToken, backupCode: backupCodes[0].toUpperCase() } })).status).toBe(200);
    const second = await h.login();
    expect((await h.call('POST', '/auth/login/2fa', { body: { mfaToken: second.body.mfaToken, backupCode: backupCodes[0] } })).status).toBe(401);
    expect((await h.call('POST', '/auth/login/2fa', { body: { mfaToken: second.body.mfaToken, backupCode: backupCodes[1] } })).status).toBe(200);
  });

  it('refuses an access token as an mfa token and bad inputs', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    await h.enableTwoFactor(accessToken);
    expect((await h.call('POST', '/auth/login/2fa', { body: { mfaToken: accessToken, code: '123456' } })).status).toBe(401);
    const { body } = await h.login();
    expect((await h.call('POST', '/auth/login/2fa', { body: { mfaToken: body.mfaToken } })).status).toBe(400);
    expect((await h.call('POST', '/auth/login/2fa', { body: { mfaToken: body.mfaToken, code: 'abcdef' } })).status).toBe(400);
  });
});

describe('turning two-factor off', () => {
  it('needs the password and a valid code', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const { secret } = await h.enableTwoFactor(accessToken);
    await clearReplayGuard();

    const noPassword = await h.call('POST', '/auth/2fa/disable', { token: accessToken, body: { password: 'wrong password!!', code: currentCode(secret) } });
    expect(noPassword.status).toBe(401);
    const noCode = await h.call('POST', '/auth/2fa/disable', { token: accessToken, body: { password: PASSWORD, code: '000000' } });
    expect(noCode.status).toBe(401);

    const ok = await h.call('POST', '/auth/2fa/disable', { token: accessToken, body: { password: PASSWORD, code: currentCode(secret) } });
    expect(ok.status).toBe(204);
    expect((await pool.query('SELECT count(*)::int AS n FROM backup_codes')).rows[0].n).toBe(0);
    expect((await h.login()).body.accessToken).toBeDefined();
  });
});
