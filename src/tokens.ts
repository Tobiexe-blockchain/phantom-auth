import jwt from 'jsonwebtoken';
import type { Config } from './config.js';
import { AppError } from './errors.js';

export type TokenType = 'access' | 'mfa';
export interface TokenClaims {
  sub: string;
  typ: TokenType;
  tv?: number;
}

export interface Tokens {
  signAccess(userId: string, tokenVersion: number): string;
  signMfa(userId: string): string;
  verify(token: string, expected: TokenType): TokenClaims;
}

export function createTokens(cfg: Pick<Config, 'jwtSecret' | 'issuer' | 'audience' | 'accessTtlSec' | 'mfaTokenTtlSec'>): Tokens {
  const base = { algorithm: 'HS256' as const, issuer: cfg.issuer, audience: cfg.audience };
  return {
    signAccess: (userId, tv) => jwt.sign({ typ: 'access', tv }, cfg.jwtSecret, { ...base, subject: userId, expiresIn: cfg.accessTtlSec }),
    signMfa: (userId) => jwt.sign({ typ: 'mfa' }, cfg.jwtSecret, { ...base, subject: userId, expiresIn: cfg.mfaTokenTtlSec }),
    verify(token, expected) {
      try {
        // Pin the algorithm so "alg: none" and algorithm-confusion tokens are rejected.
        const p = jwt.verify(token, cfg.jwtSecret, { algorithms: ['HS256'], issuer: cfg.issuer, audience: cfg.audience }) as jwt.JwtPayload;
        if (p.typ !== expected || typeof p.sub !== 'string') throw new Error('wrong token type');
        return { sub: p.sub, typ: p.typ, tv: p.tv };
      } catch {
        throw new AppError(401, 'INVALID_TOKEN', 'The token is missing, expired, or invalid.');
      }
    },
  };
}
