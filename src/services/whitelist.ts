import type { Pool } from 'pg';
import { audit, type RequestContext } from '../audit.js';
import type { Config } from '../config.js';
import { randomToken, sha256 } from '../crypto.js';
import { AppError } from '../errors.js';
import type { Mailer } from '../mailer.js';

export type Network = 'ethereum' | 'bitcoin';

/** Syntax checks only. Checksum validation (EIP-55, base58check, bech32) belongs here before production. */
const NETWORKS: Record<Network, { test(a: string): boolean; normalize(a: string): string }> = {
  ethereum: { test: (a) => /^0x[0-9a-fA-F]{40}$/.test(a), normalize: (a) => a.toLowerCase() },
  bitcoin: {
    test: (a) => /^(bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(/^bc1/i.test(a) ? a.toLowerCase() : a),
    normalize: (a) => (/^bc1/i.test(a) ? a.toLowerCase() : a),
  },
};

export type WhitelistStatus = 'pending_confirmation' | 'cooling_down' | 'active' | 'revoked';

export interface WhitelistEntry {
  id: string;
  network: string;
  address: string;
  label: string | null;
  status: WhitelistStatus;
  createdAt: string;
  activeAt: string;
  confirmedAt: string | null;
}

const STATUS_SQL = `CASE
  WHEN revoked_at IS NOT NULL THEN 'revoked'
  WHEN confirmed_at IS NULL THEN 'pending_confirmation'
  WHEN now() < active_at THEN 'cooling_down'
  ELSE 'active' END`;
const COLS = `id, network, address, label, (${STATUS_SQL}) AS status, created_at, active_at, confirmed_at`;
const toEntry = (r: any): WhitelistEntry => ({
  id: r.id,
  network: r.network,
  address: r.address,
  label: r.label,
  status: r.status,
  createdAt: r.created_at.toISOString(),
  activeAt: r.active_at.toISOString(),
  confirmedAt: r.confirmed_at ? r.confirmed_at.toISOString() : null,
});

/**
 * Withdrawal address whitelist. A new address must be confirmed by the signed-in owner using a token
 * sent by email, and then cannot receive withdrawals until the cooling-off period has passed.
 * The delay gives the real owner time to notice and remove an address added by an attacker.
 */
export class WhitelistService {
  constructor(
    private readonly pool: Pool,
    private readonly cfg: Config,
    private readonly mailer: Mailer,
  ) {}

  async add(userId: string, email: string, input: { network: Network; address: string; label?: string }, ctx: RequestContext): Promise<WhitelistEntry> {
    const net = NETWORKS[input.network];
    const raw = input.address.trim();
    if (!net.test(raw)) throw new AppError(400, 'INVALID_ADDRESS', `That is not a valid ${input.network} address.`);
    const address = net.normalize(raw);

    const count = await this.pool.query('SELECT count(*)::int AS n FROM whitelist_addresses WHERE user_id = $1 AND revoked_at IS NULL', [userId]);
    if (count.rows[0].n >= this.cfg.whitelistMaxEntries) {
      throw new AppError(422, 'WHITELIST_FULL', `You can keep up to ${this.cfg.whitelistMaxEntries} addresses. Remove one first.`);
    }

    const token = randomToken();
    let entry: WhitelistEntry;
    try {
      const res = await this.pool.query(
        `INSERT INTO whitelist_addresses(user_id, network, address, label, confirm_token_hash, active_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
         RETURNING ${COLS}`,
        [userId, input.network, address, input.label ?? null, sha256(token), this.cfg.whitelistDelayHours * 3600],
      );
      entry = toEntry(res.rows[0]);
    } catch (err) {
      if ((err as { code?: string }).code === '23505') throw new AppError(409, 'ALREADY_WHITELISTED', 'This address is already on your list.');
      throw err;
    }
    await audit(this.pool, 'whitelist_added', userId, ctx, { id: entry.id, network: input.network });
    try {
      await this.mailer.sendWhitelistConfirmation({ to: email, token, network: input.network, address });
    } catch {
      await audit(this.pool, 'whitelist_mail_failed', userId, ctx, { id: entry.id });
    }
    return entry;
  }

  /** The token alone is not enough: the signed-in user must own the entry. */
  async confirm(userId: string, token: string, ctx: RequestContext): Promise<WhitelistEntry> {
    const res = await this.pool.query(
      `UPDATE whitelist_addresses SET confirmed_at = now(), confirm_token_hash = NULL
        WHERE user_id = $1 AND confirm_token_hash = $2 AND confirmed_at IS NULL AND revoked_at IS NULL
        RETURNING ${COLS}`,
      [userId, sha256(token)],
    );
    if (res.rowCount === 0) throw new AppError(400, 'INVALID_CONFIRMATION', 'This confirmation link is invalid or was already used.');
    await audit(this.pool, 'whitelist_confirmed', userId, ctx, { id: res.rows[0].id });
    return toEntry(res.rows[0]);
  }

  async list(userId: string): Promise<WhitelistEntry[]> {
    const res = await this.pool.query(`SELECT ${COLS} FROM whitelist_addresses WHERE user_id = $1 ORDER BY created_at DESC`, [userId]);
    return res.rows.map(toEntry);
  }

  /** Removal takes effect immediately. Removing is always safe, adding is what needs a delay. */
  async remove(userId: string, id: string, ctx: RequestContext): Promise<void> {
    const res = await this.pool.query('UPDATE whitelist_addresses SET revoked_at = now(), confirm_token_hash = NULL WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL', [id, userId]);
    if (res.rowCount === 0) throw new AppError(404, 'NOT_FOUND', 'Address not found.');
    await audit(this.pool, 'whitelist_removed', userId, ctx, { id });
  }

  /** For the withdrawal service: may this user withdraw to this address right now? */
  async isAllowed(userId: string, network: Network, address: string): Promise<boolean> {
    const net = NETWORKS[network];
    if (!net || !net.test(address.trim())) return false;
    const res = await this.pool.query(
      `SELECT 1 FROM whitelist_addresses
        WHERE user_id = $1 AND network = $2 AND address = $3 AND revoked_at IS NULL AND confirmed_at IS NOT NULL AND active_at <= now()`,
      [userId, network, net.normalize(address.trim())],
    );
    return res.rowCount === 1;
  }
}
