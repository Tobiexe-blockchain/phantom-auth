import type { Pool } from 'pg';
import { buildApp } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';
import { createPool } from '../src/db.js';
import { MemoryMailer } from '../src/mailer.js';
import { migrate } from '../src/migrate.js';
import { currentCode } from '../src/totp.js';

export const DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/phantom_auth';
export const PASSWORD = 'correct horse battery staple';
export const ETH_ADDRESS = '0x52908400098527886E0F7030069857D2E4169EE7';

export async function setupDb(): Promise<Pool> {
  const pool = createPool(DATABASE_URL, 30);
  await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  await migrate(DATABASE_URL);
  return pool;
}

export async function resetDb(pool: Pool): Promise<void> {
  await pool.query('TRUNCATE users, audit_log RESTART IDENTITY CASCADE');
}

export interface Reply {
  status: number;
  body: any;
  headers: Record<string, unknown>;
}

export function makeApp(pool: Pool, overrides: Partial<Config> = {}) {
  const config: Config = {
    ...loadConfig({
      DATABASE_URL,
      JWT_SECRET: 'test-secret-test-secret-test-secret-123456',
      TOTP_ENCRYPTION_KEY: 'ab'.repeat(32),
      ARGON2_MEMORY_KIB: '8192',
      ARGON2_TIME_COST: '1',
      RATE_LIMIT_PER_MINUTE: '100000',
      IP_FAILED_LOGIN_MAX: '1000',
    }),
    ...overrides,
  };
  const mailer = new MemoryMailer();
  const app = buildApp({ pool, config, mailer });

  async function call(method: 'GET' | 'POST' | 'DELETE', url: string, opts: { body?: unknown; token?: string; headers?: Record<string, string> } = {}): Promise<Reply> {
    const res = await app.inject({
      method,
      url,
      payload: opts.body as object | undefined,
      headers: { ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}), ...opts.headers },
    });
    let body: any = null;
    try {
      body = res.body ? JSON.parse(res.body) : null;
    } catch {
      body = res.body;
    }
    return { status: res.statusCode, body, headers: res.headers };
  }

  return {
    app,
    config,
    mailer,
    call,
    async register(email = 'alice@example.com', password = PASSWORD) {
      return call('POST', '/auth/register', { body: { email, password } });
    },
    async login(email = 'alice@example.com', password = PASSWORD) {
      return call('POST', '/auth/login', { body: { email, password } });
    },
    /** Registers, logs in and returns the session. */
    async signIn(email = 'alice@example.com') {
      const reg = await call('POST', '/auth/register', { body: { email, password: PASSWORD } });
      if (reg.status !== 201) throw new Error(`register failed: ${JSON.stringify(reg.body)}`);
      const res = await call('POST', '/auth/login', { body: { email, password: PASSWORD } });
      return { userId: reg.body.id as string, accessToken: res.body.accessToken as string, refreshToken: res.body.refreshToken as string };
    },
    async enableTwoFactor(token: string) {
      const setup = await call('POST', '/auth/2fa/setup', { token });
      const enable = await call('POST', '/auth/2fa/enable', { token, body: { code: currentCode(setup.body.secret) } });
      if (enable.status !== 200) throw new Error(`enable failed: ${JSON.stringify(enable.body)}`);
      return { secret: setup.body.secret as string, backupCodes: enable.body.backupCodes as string[] };
    },
  };
}
