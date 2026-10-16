import { RateLimiterMemory, type RateLimiterRes } from 'rate-limiter-flexible';
import type { Config } from './config.js';
import { AppError } from './errors.js';

export interface Limiters {
  /** Counts every request per IP. */
  assertWithinRequestLimit(ip: string): Promise<void>;
  /** Throws when this IP has too many failed logins. */
  assertNotBlocked(ip: string): Promise<void>;
  recordFailure(ip: string): Promise<void>;
}

const tooMany = (res: RateLimiterRes) =>
  new AppError(429, 'RATE_LIMITED', 'Too many requests. Wait a moment and try again.', { retryAfterSec: Math.max(1, Math.ceil(res.msBeforeNext / 1000)) });

/** In-memory limits. Behind several instances, swap RateLimiterMemory for RateLimiterRedis. */
export function createLimiters(cfg: Pick<Config, 'rateLimitPerMinute' | 'ipFailedLoginMax'>): Limiters {
  const requests = new RateLimiterMemory({ points: cfg.rateLimitPerMinute, duration: 60 });
  const failures = new RateLimiterMemory({ points: cfg.ipFailedLoginMax, duration: 15 * 60, blockDuration: 15 * 60 });
  return {
    async assertWithinRequestLimit(ip) {
      try {
        await requests.consume(ip);
      } catch (res) {
        throw tooMany(res as RateLimiterRes);
      }
    },
    async assertNotBlocked(ip) {
      const res = await failures.get(ip);
      if (res && res.remainingPoints <= 0) throw tooMany(res);
    },
    async recordFailure(ip) {
      await failures.consume(ip).catch(() => undefined);
    },
  };
}
