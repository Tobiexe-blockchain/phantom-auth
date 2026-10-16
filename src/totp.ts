import { authenticator } from 'otplib';

authenticator.options = { window: 1, digits: 6, step: 30 };

export const generateSecret = (): string => authenticator.generateSecret();
export const keyUri = (email: string, secret: string): string => authenticator.keyuri(email, 'Phantom Exchange', secret);
export const currentCode = (secret: string, stepOffset = 0): string => {
  const saved = authenticator.options;
  authenticator.options = { ...saved, epoch: Date.now() + stepOffset * 30_000 };
  try {
    return authenticator.generate(secret);
  } finally {
    authenticator.options = saved;
  }
};

/**
 * Returns the time step the code belongs to, or null if the code is wrong or already used.
 * A code is accepted once: its step must be newer than the last step this user consumed.
 */
export function verifyTotp(secret: string, token: string, lastStep: number | null): number | null {
  const delta = authenticator.checkDelta(token, secret);
  if (delta === null || delta === undefined) return null;
  const step = Math.floor(Date.now() / 30_000) + delta;
  if (lastStep !== null && step <= lastStep) return null;
  return step;
}
