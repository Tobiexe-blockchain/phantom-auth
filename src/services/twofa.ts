import QRCode from 'qrcode';
import type { Pool } from 'pg';
import { audit, type RequestContext } from '../audit.js';
import type { Config } from '../config.js';
import { decrypt, encrypt, generateBackupCode, normalizeBackupCode } from '../crypto.js';
import { withTx } from '../db.js';
import { AppError } from '../errors.js';
import type { Hasher } from '../passwords.js';
import { generateSecret, keyUri, verifyTotp } from '../totp.js';
import type { AuthService } from './auth.js';

const BACKUP_CODE_COUNT = 10;

export class TwoFactorService {
  constructor(
    private readonly pool: Pool,
    private readonly cfg: Config,
    private readonly hasher: Hasher,
    private readonly auth: AuthService,
  ) {}

  /** Creates a pending secret. 2FA is not active until the user proves they can generate a code. */
  async setup(userId: string): Promise<{ secret: string; otpauthUrl: string; qrCodeDataUrl: string }> {
    const user = await this.auth.getUserById(userId);
    if (!user) throw new AppError(401, 'INVALID_TOKEN', 'The token is missing, expired, or invalid.');
    if (user.totp_enabled) throw new AppError(409, 'ALREADY_ENABLED', 'Two-factor authentication is already on. Turn it off first to set it up again.');
    const secret = generateSecret();
    await this.pool.query('UPDATE users SET totp_secret_enc = $2, last_totp_step = NULL WHERE id = $1', [userId, encrypt(secret, this.cfg.totpKeyHex)]);
    const otpauthUrl = keyUri(user.email, secret);
    return { secret, otpauthUrl, qrCodeDataUrl: await QRCode.toDataURL(otpauthUrl) };
  }

  /** Activates 2FA and returns one-time backup codes. The codes are shown once and stored hashed. */
  async enable(userId: string, code: string, ctx: RequestContext): Promise<{ backupCodes: string[] }> {
    const user = await this.auth.getUserById(userId);
    if (!user) throw new AppError(401, 'INVALID_TOKEN', 'The token is missing, expired, or invalid.');
    if (user.totp_enabled) throw new AppError(409, 'ALREADY_ENABLED', 'Two-factor authentication is already on.');
    if (!user.totp_secret_enc) throw new AppError(400, 'NO_PENDING_SETUP', 'Start setup first to get a secret and QR code.');
    if (user.is_locked) throw new AppError(429, 'ACCOUNT_LOCKED', 'Too many failed attempts. Try again later.', { retryAfterSec: user.retry_after ?? 0 });

    const step = verifyTotp(decrypt(user.totp_secret_enc, this.cfg.totpKeyHex), code, null);
    if (step === null) {
      await this.auth.recordFailure(userId, ctx, 'mfa_enable_failed');
      throw new AppError(401, 'INVALID_CODE', 'That code is not valid. Check the time on your device and try the newest code.');
    }

    const backupCodes = Array.from({ length: BACKUP_CODE_COUNT }, generateBackupCode);
    const hashes = await Promise.all(backupCodes.map((c) => this.hasher.hash(normalizeBackupCode(c))));
    await withTx(this.pool, async (c) => {
      await c.query('UPDATE users SET totp_enabled = true, last_totp_step = $2 WHERE id = $1', [userId, step]);
      await c.query('DELETE FROM backup_codes WHERE user_id = $1', [userId]);
      for (const h of hashes) await c.query('INSERT INTO backup_codes(user_id, code_hash) VALUES ($1, $2)', [userId, h]);
      await audit(c, '2fa_enabled', userId, ctx);
    });
    return { backupCodes };
  }

  /** Turning 2FA off needs the password and a current second factor. */
  async disable(userId: string, password: string, input: { code?: string; backupCode?: string }, ctx: RequestContext): Promise<void> {
    const user = await this.auth.getUserById(userId);
    if (!user) throw new AppError(401, 'INVALID_TOKEN', 'The token is missing, expired, or invalid.');
    if (!user.totp_enabled) throw new AppError(409, 'NOT_ENABLED', 'Two-factor authentication is not on.');
    if (user.is_locked) throw new AppError(429, 'ACCOUNT_LOCKED', 'Too many failed attempts. Try again later.', { retryAfterSec: user.retry_after ?? 0 });

    if (!(await this.hasher.verify(user.password_hash, password))) {
      await this.auth.recordFailure(userId, ctx, 'mfa_disable_failed');
      throw new AppError(401, 'INVALID_CREDENTIALS', 'Password is incorrect.');
    }
    if (!(await this.auth.checkSecondFactor(user, input, ctx))) {
      await this.auth.recordFailure(userId, ctx, 'mfa_disable_failed');
      throw new AppError(401, 'INVALID_CODE', 'That code is not valid.');
    }
    await withTx(this.pool, async (c) => {
      await c.query('UPDATE users SET totp_enabled = false, totp_secret_enc = NULL, last_totp_step = NULL WHERE id = $1', [userId]);
      await c.query('DELETE FROM backup_codes WHERE user_id = $1', [userId]);
      await audit(c, '2fa_disabled', userId, ctx);
    });
  }
}
