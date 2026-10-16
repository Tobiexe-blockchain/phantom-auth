import { z } from 'zod';

const schema = z.object({
  DATABASE_URL: z.string().default('postgres://postgres:postgres@localhost:5432/phantom_auth'),
  PORT: z.coerce.number().int().default(3001),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  TOTP_ENCRYPTION_KEY: z.string().regex(/^[0-9a-fA-F]{64}$/, 'TOTP_ENCRYPTION_KEY must be 64 hex characters (32 bytes)'),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  TRUST_PROXY: z.enum(['true', 'false']).default('false'),
  ISSUER: z.string().default('phantom-auth'),
  AUDIENCE: z.string().default('phantom-exchange'),
  ACCESS_TTL_SEC: z.coerce.number().int().positive().default(900),
  REFRESH_TTL_DAYS: z.coerce.number().int().positive().default(30),
  MFA_TOKEN_TTL_SEC: z.coerce.number().int().positive().default(300),
  ARGON2_MEMORY_KIB: z.coerce.number().int().min(8192).default(19456),
  ARGON2_TIME_COST: z.coerce.number().int().min(1).default(2),
  MAX_FAILED_ATTEMPTS: z.coerce.number().int().positive().default(5),
  LOCKOUT_MINUTES: z.coerce.number().int().positive().default(15),
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(60),
  IP_FAILED_LOGIN_MAX: z.coerce.number().int().positive().default(10),
  WHITELIST_DELAY_HOURS: z.coerce.number().positive().default(24),
  WHITELIST_MAX_ENTRIES: z.coerce.number().int().positive().default(25),
});

export interface Config {
  databaseUrl: string;
  port: number;
  jwtSecret: string;
  totpKeyHex: string;
  corsOrigins: string[];
  trustProxy: boolean;
  issuer: string;
  audience: string;
  accessTtlSec: number;
  refreshTtlDays: number;
  mfaTokenTtlSec: number;
  argon2MemoryKiB: number;
  argon2TimeCost: number;
  maxFailedAttempts: number;
  lockoutMinutes: number;
  rateLimitPerMinute: number;
  ipFailedLoginMax: number;
  whitelistDelayHours: number;
  whitelistMaxEntries: number;
}

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const e = schema.parse(env);
  return {
    databaseUrl: e.DATABASE_URL,
    port: e.PORT,
    jwtSecret: e.JWT_SECRET,
    totpKeyHex: e.TOTP_ENCRYPTION_KEY,
    corsOrigins: e.CORS_ORIGIN.split(',').map((s) => s.trim()).filter(Boolean),
    trustProxy: e.TRUST_PROXY === 'true',
    issuer: e.ISSUER,
    audience: e.AUDIENCE,
    accessTtlSec: e.ACCESS_TTL_SEC,
    refreshTtlDays: e.REFRESH_TTL_DAYS,
    mfaTokenTtlSec: e.MFA_TOKEN_TTL_SEC,
    argon2MemoryKiB: e.ARGON2_MEMORY_KIB,
    argon2TimeCost: e.ARGON2_TIME_COST,
    maxFailedAttempts: e.MAX_FAILED_ATTEMPTS,
    lockoutMinutes: e.LOCKOUT_MINUTES,
    rateLimitPerMinute: e.RATE_LIMIT_PER_MINUTE,
    ipFailedLoginMax: e.IP_FAILED_LOGIN_MAX,
    whitelistDelayHours: e.WHITELIST_DELAY_HOURS,
    whitelistMaxEntries: e.WHITELIST_MAX_ENTRIES,
  };
}
