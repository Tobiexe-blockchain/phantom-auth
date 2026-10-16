import type { Pool, PoolClient } from 'pg';

export interface RequestContext {
  ip?: string;
  userAgent?: string;
}

export async function audit(
  db: Pool | PoolClient,
  event: string,
  userId: string | null,
  ctx: RequestContext = {},
  metadata: Record<string, unknown> = {},
): Promise<void> {
  await db.query('INSERT INTO audit_log(user_id, event, ip, user_agent, metadata) VALUES ($1, $2, $3, $4, $5)', [
    userId,
    event,
    ctx.ip ?? null,
    ctx.userAgent?.slice(0, 200) ?? null,
    JSON.stringify(metadata),
  ]);
}
