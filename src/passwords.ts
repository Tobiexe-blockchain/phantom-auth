import argon2 from 'argon2';

export interface Hasher {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
}

export function createHasher(opts: { memoryKiB: number; timeCost: number }): Hasher {
  const options = { type: argon2.argon2id as 2, memoryCost: opts.memoryKiB, timeCost: opts.timeCost, parallelism: 1 };
  return {
    hash: (password) => argon2.hash(password, options),
    verify: (hash, password) => argon2.verify(hash, password).catch(() => false),
  };
}
