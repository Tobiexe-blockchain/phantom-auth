import { createCipheriv, createDecipheriv, createHash, randomBytes, randomInt } from 'node:crypto';

export const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

/** URL-safe random token with 256 bits of entropy by default. */
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString('base64url');

// No 0/o/1/l/i so codes are easy to read aloud and type.
const CODE_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

/** Backup code like "k3m9x-p2qrt" (about 49 bits). */
export function generateBackupCode(): string {
  const pick = () => Array.from({ length: 5 }, () => CODE_ALPHABET[randomInt(CODE_ALPHABET.length)]).join('');
  return `${pick()}-${pick()}`;
}

export const normalizeBackupCode = (code: string): string => code.trim().toLowerCase();

/** AES-256-GCM. Output is iv.tag.ciphertext, each base64. */
export function encrypt(plain: string, keyHex: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ct].map((b) => b.toString('base64')).join('.');
}

export function decrypt(payload: string, keyHex: string): string {
  const [iv, tag, ct] = payload.split('.').map((p) => Buffer.from(p, 'base64'));
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}
