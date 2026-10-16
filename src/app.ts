import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import { createHash, timingSafeEqual } from 'node:crypto';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { z, ZodError } from 'zod';
import type { RequestContext } from './audit.js';
import type { Config } from './config.js';
import { AppError } from './errors.js';
import type { Mailer } from './mailer.js';
import { createHasher } from './passwords.js';
import { createLimiters } from './rateLimit.js';
import { AuthService } from './services/auth.js';
import { TwoFactorService } from './services/twofa.js';
import { WhitelistService } from './services/whitelist.js';
import { createTokens } from './tokens.js';

declare module 'fastify' {
  interface FastifyRequest {
    userId?: string;
    userEmail?: string;
  }
}

const email = z.string().trim().toLowerCase().max(254).email();
const password = z.string().min(12, 'Use at least 12 characters.').max(128, 'Use at most 128 characters.');
const totpCode = z.string().regex(/^\d{6}$/, 'Enter the 6 digit code.');
const backupCode = z.string().trim().min(5).max(20);
const secondFactor = z.object({ code: totpCode.optional(), backupCode: backupCode.optional() });
const refreshToken = z.string().min(20).max(200);

const schemas = {
  register: z.object({ email, password }).strict(),
  login: z.object({ email, password: z.string().min(1).max(128) }).strict(),
  login2fa: z.object({ mfaToken: z.string().min(20).max(2000) }).and(secondFactor),
  refresh: z.object({ refreshToken }).strict(),
  enable2fa: z.object({ code: totpCode }).strict(),
  disable2fa: z.object({ password: z.string().min(1).max(128) }).and(secondFactor),
  whitelistAdd: z.object({ network: z.enum(['ethereum', 'bitcoin']), address: z.string().trim().min(10).max(100), label: z.string().trim().max(60).optional() }).and(secondFactor),
  whitelistConfirm: z.object({ token: z.string().min(20).max(200) }).strict(),
  idParam: z.object({ id: z.string().uuid() }),
  allowedQuery: z.object({ network: z.enum(['ethereum', 'bitcoin']), address: z.string().min(10).max(100) }),
  internalAllowed: z.object({ userId: z.string().uuid(), network: z.enum(['ethereum', 'bitcoin']), address: z.string().min(10).max(100) }),
  auditQuery: z.object({ limit: z.coerce.number().int().min(1).max(200).default(50) }),
};

function requireOneFactor(f: { code?: string; backupCode?: string }, required: boolean): void {
  if (!f.code && !f.backupCode) {
    if (required) throw new AppError(400, 'SECOND_FACTOR_REQUIRED', 'Enter your authenticator code or a backup code.');
    return;
  }
  if (f.code && f.backupCode) throw new AppError(400, 'VALIDATION_ERROR', 'Send either code or backupCode, not both.');
}

export interface AppDeps {
  pool: Pool;
  config: Config;
  mailer: Mailer;
}

export function buildApp({ pool, config, mailer }: AppDeps): FastifyInstance {
  const app = Fastify({ logger: false, trustProxy: config.trustProxy, bodyLimit: 16 * 1024 });
  const hasher = createHasher({ memoryKiB: config.argon2MemoryKiB, timeCost: config.argon2TimeCost });
  const tokens = createTokens(config);
  const limiters = createLimiters(config);
  const auth = new AuthService(pool, config, hasher, tokens);
  const twofa = new TwoFactorService(pool, config, hasher, auth);
  const whitelist = new WhitelistService(pool, config, mailer);

  app.register(helmet);
  app.register(cors, { origin: config.corsOrigins, methods: ['GET', 'POST', 'DELETE'] });

  const ctx = (req: FastifyRequest): RequestContext => ({ ip: req.ip, userAgent: req.headers['user-agent'] });

  app.setErrorHandler((err: any, _req, reply) => {
    if (err instanceof AppError) {
      const retry = err.details?.retryAfterSec;
      if (typeof retry === 'number') reply.header('Retry-After', String(retry));
      return reply.status(err.status).send({ error: { code: err.code, message: err.message, details: err.details } });
    }
    if (err instanceof ZodError) {
      return reply.status(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Some fields need fixing.', details: err.issues.map((i) => ({ field: i.path.join('.'), message: i.message })) },
      });
    }
    if (typeof err.statusCode === 'number' && err.statusCode < 500) {
      return reply.status(err.statusCode).send({ error: { code: 'BAD_REQUEST', message: 'The request could not be read.' } });
    }
    console.error(err);
    return reply.status(500).send({ error: { code: 'INTERNAL', message: 'Something went wrong on our side.' } });
  });
  app.setNotFoundHandler((_req, reply) => reply.status(404).send({ error: { code: 'NOT_FOUND', message: 'Route not found.' } }));

  // Internal routes are guarded by the service key instead, and only wrong keys use up the IP budget.
  app.addHook('onRequest', async (req) => {
    if (req.url !== '/health' && !req.url.startsWith('/internal/')) await limiters.assertWithinRequestLimit(req.ip);
  });

  const digest = (v: string) => createHash('sha256').update(v).digest();
  async function requireServiceKey(req: FastifyRequest): Promise<void> {
    if (!config.serviceApiKey) throw new AppError(404, 'NOT_FOUND', 'Route not found.');
    const given = req.headers['x-service-key'];
    if (typeof given !== 'string' || !timingSafeEqual(digest(given), digest(config.serviceApiKey))) {
      await limiters.assertWithinRequestLimit(req.ip);
      throw new AppError(401, 'UNAUTHORIZED', 'A valid x-service-key header is required.');
    }
  }

  async function authenticate(req: FastifyRequest): Promise<void> {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) throw new AppError(401, 'INVALID_TOKEN', 'The token is missing, expired, or invalid.');
    const claims = tokens.verify(header.slice(7), 'access');
    const user = await auth.getUserById(claims.sub);
    // token_version lets logout-all end access tokens that have not expired yet.
    if (!user || user.token_version !== claims.tv) throw new AppError(401, 'INVALID_TOKEN', 'The token is missing, expired, or invalid.');
    req.userId = user.id;
    req.userEmail = user.email;
  }
  const authed = { preHandler: authenticate };

  app.get('/health', async () => ({ status: 'ok' }));

  // ---------- accounts and sessions ----------
  app.post('/auth/register', async (req, reply) => {
    const body = schemas.register.parse(req.body);
    const local = body.email.split('@')[0];
    if (local.length >= 4 && body.password.toLowerCase().includes(local)) {
      throw new AppError(400, 'WEAK_PASSWORD', 'The password should not contain your email name.');
    }
    return reply.status(201).send(await auth.register(body.email, body.password, ctx(req)));
  });

  app.post('/auth/login', async (req) => {
    const body = schemas.login.parse(req.body);
    await limiters.assertNotBlocked(req.ip);
    try {
      const result = await auth.login(body.email, body.password, ctx(req));
      return result;
    } catch (err) {
      if (err instanceof AppError && err.code === 'INVALID_CREDENTIALS') await limiters.recordFailure(req.ip);
      throw err;
    }
  });

  app.post('/auth/login/2fa', async (req) => {
    const body = schemas.login2fa.parse(req.body);
    requireOneFactor(body, true);
    await limiters.assertNotBlocked(req.ip);
    try {
      return { mfaRequired: false, ...(await auth.completeMfa(body.mfaToken, body, ctx(req))) };
    } catch (err) {
      if (err instanceof AppError && err.code === 'INVALID_CODE') await limiters.recordFailure(req.ip);
      throw err;
    }
  });

  app.post('/auth/refresh', async (req) => auth.refresh(schemas.refresh.parse(req.body).refreshToken, ctx(req)));

  app.post('/auth/logout', async (req, reply) => {
    await auth.logout(schemas.refresh.parse(req.body).refreshToken, ctx(req));
    return reply.status(204).send();
  });

  app.post('/auth/logout-all', authed, async (req, reply) => {
    await auth.logoutAll(req.userId!, ctx(req));
    return reply.status(204).send();
  });

  app.get('/auth/me', authed, async (req) => {
    const user = (await auth.getUserById(req.userId!))!;
    return { id: user.id, email: user.email, twoFactorEnabled: user.totp_enabled };
  });

  // ---------- two-factor ----------
  app.post('/auth/2fa/setup', authed, async (req) => twofa.setup(req.userId!));
  app.post('/auth/2fa/enable', authed, async (req) => twofa.enable(req.userId!, schemas.enable2fa.parse(req.body).code, ctx(req)));
  app.post('/auth/2fa/disable', authed, async (req, reply) => {
    const body = schemas.disable2fa.parse(req.body);
    requireOneFactor(body, true);
    await twofa.disable(req.userId!, body.password, body, ctx(req));
    return reply.status(204).send();
  });

  // ---------- withdrawal address whitelist ----------
  app.post('/whitelist', authed, async (req, reply) => {
    const body = schemas.whitelistAdd.parse(req.body);
    const user = (await auth.getUserById(req.userId!))!;
    requireOneFactor(body, user.totp_enabled);
    if (user.totp_enabled) {
      if (user.is_locked) throw new AppError(429, 'ACCOUNT_LOCKED', 'Too many failed attempts. Try again later.', { retryAfterSec: user.retry_after ?? 0 });
      if (!(await auth.checkSecondFactor(user, body, ctx(req)))) {
        await auth.recordFailure(user.id, ctx(req), 'whitelist_mfa_failed');
        throw new AppError(401, 'INVALID_CODE', 'That code is not valid.');
      }
    }
    return reply.status(201).send(await whitelist.add(user.id, user.email, body, ctx(req)));
  });
  app.get('/whitelist', authed, async (req) => whitelist.list(req.userId!));
  app.post('/whitelist/confirm', authed, async (req) => whitelist.confirm(req.userId!, schemas.whitelistConfirm.parse(req.body).token, ctx(req)));
  app.delete('/whitelist/:id', authed, async (req, reply) => {
    await whitelist.remove(req.userId!, schemas.idParam.parse(req.params).id, ctx(req));
    return reply.status(204).send();
  });
  app.get('/whitelist/allowed', authed, async (req) => {
    const q = schemas.allowedQuery.parse(req.query);
    return { allowed: await whitelist.isAllowed(req.userId!, q.network, q.address) };
  });

  // ---------- service to service ----------
  // The wallet service asks this before sending a withdrawal. Called with a service key, not a user token.
  app.get('/internal/whitelist/allowed', async (req) => {
    await requireServiceKey(req);
    const q = schemas.internalAllowed.parse(req.query);
    return { allowed: await whitelist.isAllowed(q.userId, q.network, q.address) };
  });

  // ---------- audit ----------
  app.get('/audit', authed, async (req) => {
    const { limit } = schemas.auditQuery.parse(req.query);
    const res = await pool.query('SELECT id, event, ip, user_agent, metadata, created_at FROM audit_log WHERE user_id = $1 ORDER BY id DESC LIMIT $2', [req.userId, limit]);
    return res.rows.map((r) => ({ id: r.id, event: r.event, ip: r.ip, userAgent: r.user_agent, metadata: r.metadata, createdAt: r.created_at }));
  });

  return app;
}
