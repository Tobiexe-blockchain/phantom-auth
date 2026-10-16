# phantom-auth

Authentication and account security service for a crypto exchange. It handles sign-up and sign-in, short-lived access tokens with rotating refresh tokens, authenticator-app two-factor login with backup codes, lockout and rate limits, a withdrawal address whitelist with a cooling-off period, and an append-only audit log.

> Demo and portfolio project. It has not been audited. Review it and add the items under "Before production" before it protects real accounts.

## What it does

| Area | Behavior |
|---|---|
| Passwords | argon2id, 12 to 128 characters, no email name inside the password. |
| Access tokens | JWT (HS256, pinned), 15 minutes, issuer and audience checked. |
| Refresh tokens | Random 256-bit tokens stored as SHA-256 hashes. Each token works once and is replaced on use. |
| Reuse detection | Using an already-rotated token ends that whole session family. Other devices stay signed in. |
| Logout | `/auth/logout` ends one session. `/auth/logout-all` ends all sessions and kills unexpired access tokens. |
| Two-factor | TOTP with QR setup, 10 one-time backup codes, replay protection, secrets encrypted at rest. |
| Lockout | 5 failed attempts lock the account for 15 minutes, including wrong second-factor codes. |
| Rate limits | Per-IP request limit, plus a per-IP block after repeated failed logins. |
| Whitelist | New withdrawal addresses need an emailed confirmation from the signed-in owner, then a 24 hour cooling-off before they can be used. Removal is immediate. |
| Audit log | Logins, failures, lockouts, reuse, 2FA changes, and whitelist changes. Database triggers block edits and deletes. |

## Run it

```bash
docker compose up -d
cp .env.example .env        # fill in JWT_SECRET and TOTP_ENCRYPTION_KEY (commands are in the file)
npm install
npm run dev                 # applies migrations, listens on :3001
npm test                    # needs the database running
```

The server refuses to start without both secrets.

## API

Errors look like `{ "error": { "code": "...", "message": "..." } }`.

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/register` | `{ email, password }` |
| POST | `/auth/login` | Returns tokens, or `{ mfaRequired: true, mfaToken }` when 2FA is on. |
| POST | `/auth/login/2fa` | `{ mfaToken, code }` or `{ mfaToken, backupCode }` |
| POST | `/auth/refresh` | `{ refreshToken }` returns a new pair |
| POST | `/auth/logout` | `{ refreshToken }` |
| POST | `/auth/logout-all` | Bearer token |
| GET | `/auth/me` | Bearer token |
| POST | `/auth/2fa/setup` | Returns the secret, `otpauth://` URL, and a QR code data URL |
| POST | `/auth/2fa/enable` | `{ code }` returns the backup codes once |
| POST | `/auth/2fa/disable` | `{ password, code \| backupCode }` |
| POST | `/whitelist` | `{ network, address, label?, code? }` (`code` is required when 2FA is on) |
| GET | `/whitelist` | Status per address: `pending_confirmation`, `cooling_down`, `active`, `revoked` |
| POST | `/whitelist/confirm` | `{ token }` from the email, signed in as the owner |
| DELETE | `/whitelist/:id` | Removes immediately |
| GET | `/whitelist/allowed` | `?network=&address=` for the withdrawal service to check before paying out |
| GET | `/audit` | The caller's own recent events |

```bash
curl -X POST localhost:3001/auth/register -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"a long passphrase 2026"}'
curl -X POST localhost:3001/auth/login -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"a long passphrase 2026"}'
```

## Threat model

| Threat | What the service does | Where it is tested |
|---|---|---|
| Password guessing against one account | Lockout after 5 failures, counted atomically so parallel guesses cannot beat the limit. | `lockout.test.ts` |
| Password spraying from one IP | Per-IP block after repeated failures across accounts. | `lockout.test.ts` |
| Leaked password database | argon2id with per-hash salts. | `auth.test.ts` |
| Account enumeration at login | Same response for a wrong password and an unknown email, with a dummy hash check to keep timing similar. | `auth.test.ts` |
| Stolen refresh token | One-time use. Replaying a rotated token ends the session family and is audited. | `sessions.test.ts` |
| Race on refresh | Row locking lets exactly one concurrent refresh win. | `sessions.test.ts` |
| Forged or downgraded JWT | Algorithm pinned to HS256. Unsigned, wrong-key, wrong-audience, and expired tokens are rejected. An mfa token cannot act as an access token. | `auth.test.ts` |
| Access token still alive after "log out everywhere" | A token version in the database is checked on every request. | `sessions.test.ts` |
| Stolen password without the phone | The password step yields only a 5 minute mfa token, never a session. | `twofa.test.ts` |
| Replaying a captured TOTP code | Each time step is accepted once, enforced with a conditional update. | `twofa.test.ts` |
| Database leak exposing TOTP secrets | Secrets are encrypted with AES-256-GCM using a key held outside the database. | `twofa.test.ts` |
| Backup code theft from the database | Codes are stored as argon2id hashes and each works once. | `twofa.test.ts` |
| Attacker with a session adds their own payout address | Needs a second factor, an emailed confirmation signed in as the owner, and a 24 hour cooling-off during which the owner can remove it. | `whitelist.test.ts` |
| Tampering with audit history | Update and delete are blocked by triggers. | `auth.test.ts` |
| Oversized or malformed input | Strict zod schemas, unknown fields rejected, 16 KB body limit, security headers from helmet. | `auth.test.ts` |

## Known limits

- Registration reveals whether an email is taken. Hiding that needs email verification, which this demo leaves out.
- Per-IP limits live in process memory. Run several instances and you need a shared store (swap in the Redis limiter from the same library).
- A client that sends the same refresh token twice, for example after a network retry, loses its session. This is the cost of strict reuse detection.
- Whitelist addresses get syntax checks only, not checksum checks.
- Email delivery is a placeholder (`Mailer`). The development mailer prints the confirmation token, so never use it in production.
- HS256 uses one shared secret. If other services must verify tokens, move to asymmetric keys (RS256 or EdDSA).

## Before production

Email verification and password reset, address checksum validation, a real mailer, key rotation for `JWT_SECRET` and `TOTP_ENCRYPTION_KEY`, a shared rate-limit store, structured logging without secrets, and an external security review.

## Structure

```
src/services/   auth (sessions, lockout, second factor), twofa, whitelist
src/            app (routes, validation), tokens, totp, crypto, passwords, rateLimit, audit, mailer, config
migrations/     SQL schema
tests/          47 tests against a real database
```
