import type { Pool, PoolClient } from 'pg';
import { audit, type RequestContext } from '../audit.js';
import type { Config } from '../config.js';
import { decrypt, normalizeBackupCode, randomToken, sha256 } from '../crypto.js';
import { withTx } from '../db.js';
import { AppError } from '../errors.js';
import type { Hasher } from '../passwords.js';
import type { Tokens } from '../tokens.js';
import { verifyTotp } from '../totp.js';

export interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  token_version: number;
  failed_attempts: number;
  totp_secret_enc: string | null;
  totp_enabled: boolean;
  last_totp_step: string | null;
  is_locked: boolean;
  retry_after: number | null;
}

export interface Session {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

export type LoginResult = ({ mfaRequired: false } & Session) | { mfaRequired: true; mfaToken: string };

const USER_COLS = `id, email, password_hash, token_version, failed_attempts, totp_secret_enc, totp_enabled, last_totp_step,
  (locked_until IS NOT NULL AND locked_until > now()) AS is_locked,
  GREATEST(0, CEIL(EXTRACT(EPOCH FROM (locked_until - now()))))::int AS retry_after`;

const invalidCredentials = () => new AppError(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
const invalidCode = () => new AppError(401, 'INVALID_CODE', 'That code is not valid. Try a new code from your authenticator app, or use a backup code.');
const locked = (u: Pick<UserRow, 'retry_after'>) =>
  new AppError(429, 'ACCOUNT_LOCKED', 'Too many failed attempts. Try again later.', { retryAfterSec: u.retry_after ?? 0 });

export class AuthService {
  private dummyHash: Promise<string>;

  constructor(
    private readonly pool: Pool,
    private readonly cfg: Config,
    private readonly hasher: Hasher,
    private readonly tokens: Tokens,
  ) {
    // Verified against when the email is unknown, so unknown and known accounts take similar time.
    this.dummyHash = hasher.hash('not-a-real-password-used-for-timing');
  }

  async register(email: string, password: string, ctx: RequestContext): Promise<{ id: string; email: string }> {
    const passwordHash = await this.hasher.hash(password);
    try {
      const res = await this.pool.query('INSERT INTO users(email, password_hash) VALUES ($1, $2) RETURNING id, email', [email, passwordHash]);
      const user = res.rows[0];
      await audit(this.pool, 'register', user.id, ctx);
      return user;
    } catch (err) {
      if ((err as { code?: string }).code === '23505') throw new AppError(409, 'EMAIL_TAKEN', 'An account with this email already exists.');
      throw err;
    }
  }

  async getUserById(id: string): Promise<UserRow | null> {
    const res = await this.pool.query(`SELECT ${USER_COLS} FROM users WHERE id = $1`, [id]);
    return res.rows[0] ?? null;
  }

  private async getUserByEmail(email: string): Promise<UserRow | null> {
    const res = await this.pool.query(`SELECT ${USER_COLS} FROM users WHERE lower(email) = lower($1)`, [email]);
    return res.rows[0] ?? null;
  }

  /** Counts one failed attempt and locks the account when the limit is reached. Atomic. */
  async recordFailure(userId: string, ctx: RequestContext, reason: string): Promise<void> {
    const res = await this.pool.query(
      `UPDATE users
          SET failed_attempts = failed_attempts + 1,
              locked_until = CASE WHEN failed_attempts + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END
        WHERE id = $1
        RETURNING failed_attempts, (locked_until IS NOT NULL AND locked_until > now()) AS is_locked`,
      [userId, this.cfg.maxFailedAttempts, this.cfg.lockoutMinutes],
    );
    await audit(this.pool, reason, userId, ctx, { failedAttempts: res.rows[0].failed_attempts });
    if (res.rows[0].is_locked && res.rows[0].failed_attempts === this.cfg.maxFailedAttempts) {
      await audit(this.pool, 'account_locked', userId, ctx, { minutes: this.cfg.lockoutMinutes });
    }
  }

  private async clearFailures(userId: string): Promise<void> {
    await this.pool.query('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1', [userId]);
  }

  /** Throws a generic 401 for wrong password, so callers cannot tell unknown emails from wrong passwords. */
  async login(email: string, password: string, ctx: RequestContext): Promise<LoginResult> {
    const user = await this.getUserByEmail(email);
    if (!user) {
      await this.hasher.verify(await this.dummyHash, password);
      await audit(this.pool, 'login_failed', null, ctx, { reason: 'unknown_email' });
      throw invalidCredentials();
    }
    if (user.is_locked) {
      await audit(this.pool, 'login_blocked_locked', user.id, ctx);
      throw locked(user);
    }
    if (!(await this.hasher.verify(user.password_hash, password))) {
      await this.recordFailure(user.id, ctx, 'login_failed');
      throw invalidCredentials();
    }
    if (user.totp_enabled) {
      // The password is right but not enough. Failures counters stay until the second step succeeds.
      await audit(this.pool, 'login_password_ok_mfa_required', user.id, ctx);
      return { mfaRequired: true, mfaToken: this.tokens.signMfa(user.id) };
    }
    await this.clearFailures(user.id);
    await audit(this.pool, 'login_success', user.id, ctx);
    return { mfaRequired: false, ...(await this.issueSession(this.pool, user.id, user.token_version, ctx)) };
  }

  /** Verifies a TOTP code (once per time step) or a backup code (once). Returns true on success. */
  async checkSecondFactor(user: UserRow, input: { code?: string; backupCode?: string }, ctx: RequestContext): Promise<boolean> {
    if (input.code && user.totp_secret_enc) {
      const secret = decrypt(user.totp_secret_enc, this.cfg.totpKeyHex);
      const step = verifyTotp(secret, input.code, user.last_totp_step === null ? null : Number(user.last_totp_step));
      if (step === null) return false;
      // Conditional update makes "use each step once" safe under concurrent requests.
      const upd = await this.pool.query('UPDATE users SET last_totp_step = $2 WHERE id = $1 AND (last_totp_step IS NULL OR last_totp_step < $2)', [user.id, step]);
      return upd.rowCount === 1;
    }
    if (input.backupCode) {
      const normalized = normalizeBackupCode(input.backupCode);
      const rows = (await this.pool.query('SELECT id, code_hash FROM backup_codes WHERE user_id = $1 AND used_at IS NULL', [user.id])).rows;
      for (const row of rows) {
        if (await this.hasher.verify(row.code_hash, normalized)) {
          const upd = await this.pool.query('UPDATE backup_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL', [row.id]);
          if (upd.rowCount === 1) {
            await audit(this.pool, 'backup_code_used', user.id, ctx);
            return true;
          }
        }
      }
    }
    return false;
  }

  async completeMfa(mfaToken: string, input: { code?: string; backupCode?: string }, ctx: RequestContext): Promise<Session> {
    const claims = this.tokens.verify(mfaToken, 'mfa');
    const user = await this.getUserById(claims.sub);
    if (!user || !user.totp_enabled) throw new AppError(401, 'INVALID_TOKEN', 'The token is missing, expired, or invalid.');
    if (user.is_locked) throw locked(user);
    if (!(await this.checkSecondFactor(user, input, ctx))) {
      await this.recordFailure(user.id, ctx, 'mfa_failed');
      throw invalidCode();
    }
    await this.clearFailures(user.id);
    await audit(this.pool, 'login_success', user.id, ctx, { mfa: true });
    return this.issueSession(this.pool, user.id, user.token_version, ctx);
  }

  async issueSession(db: Pool | PoolClient, userId: string, tokenVersion: number, ctx: RequestContext, familyId?: string): Promise<Session> {
    const refreshToken = randomToken();
    await db.query(
      `INSERT INTO refresh_tokens(user_id, family_id, token_hash, expires_at, user_agent, ip)
       VALUES ($1, COALESCE($2::uuid, gen_random_uuid()), $3, now() + make_interval(days => $4), $5, $6)`,
      [userId, familyId ?? null, sha256(refreshToken), this.cfg.refreshTtlDays, ctx.userAgent?.slice(0, 200) ?? null, ctx.ip ?? null],
    );
    return {
      accessToken: this.tokens.signAccess(userId, tokenVersion),
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: this.cfg.accessTtlSec,
    };
  }

  /**
   * Rotates a refresh token. Every token works once. Presenting an already-rotated token means it
   * leaked (or the client replayed it), so the whole family is revoked and the user must sign in again.
   */
  async refresh(rawToken: string, ctx: RequestContext): Promise<Session> {
    const outcome = await withTx(this.pool, async (c) => {
      const found = await c.query(
        `SELECT t.id, t.user_id, t.family_id, t.revoked_at, t.replaced_by, (t.expires_at <= now()) AS expired, u.token_version
           FROM refresh_tokens t JOIN users u ON u.id = t.user_id
          WHERE t.token_hash = $1 FOR UPDATE OF t`,
        [sha256(rawToken)],
      );
      const t = found.rows[0];
      if (!t) return { kind: 'invalid' as const };
      if (t.replaced_by) {
        await c.query('UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL', [t.family_id]);
        await audit(c, 'refresh_reuse_detected', t.user_id, ctx, { familyId: t.family_id });
        return { kind: 'reuse' as const };
      }
      if (t.revoked_at || t.expired) return { kind: 'invalid' as const };

      const session = await this.issueSession(c, t.user_id, t.token_version, ctx, t.family_id);
      const next = await c.query('SELECT id FROM refresh_tokens WHERE token_hash = $1', [sha256(session.refreshToken)]);
      await c.query('UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $2 WHERE id = $1', [t.id, next.rows[0].id]);
      return { kind: 'ok' as const, session };
    });
    // Thrown after the transaction commits so the family revocation is kept.
    if (outcome.kind === 'reuse') throw new AppError(401, 'REFRESH_TOKEN_REUSED', 'This session was ended because a token was used twice. Sign in again.');
    if (outcome.kind === 'invalid') throw new AppError(401, 'INVALID_REFRESH_TOKEN', 'The refresh token is invalid or expired. Sign in again.');
    return outcome.session;
  }

  /** Ends the session the token belongs to. Always succeeds, so it reveals nothing about token validity. */
  async logout(rawToken: string, ctx: RequestContext): Promise<void> {
    const res = await this.pool.query(
      `UPDATE refresh_tokens SET revoked_at = now()
        WHERE revoked_at IS NULL AND family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)
        RETURNING user_id`,
      [sha256(rawToken)],
    );
    if (res.rowCount) await audit(this.pool, 'logout', res.rows[0].user_id, ctx);
  }

  /** Ends every session, including access tokens that have not expired yet. */
  async logoutAll(userId: string, ctx: RequestContext): Promise<void> {
    await withTx(this.pool, async (c) => {
      await c.query('UPDATE users SET token_version = token_version + 1 WHERE id = $1', [userId]);
      await c.query('UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL', [userId]);
      await audit(c, 'logout_all', userId, ctx);
    });
  }
}
