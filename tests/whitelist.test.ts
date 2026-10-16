import type { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { currentCode } from '../src/totp.js';
import { ETH_ADDRESS, makeApp, resetDb, setupDb } from './helpers.js';

let pool: Pool;
beforeAll(async () => {
  pool = await setupDb();
});
afterAll(async () => {
  await pool.end();
});
beforeEach(async () => {
  await resetDb(pool);
});

const allowed = async (h: ReturnType<typeof makeApp>, token: string, address = ETH_ADDRESS) =>
  (await h.call('GET', `/whitelist/allowed?network=ethereum&address=${address}`, { token })).body.allowed;

describe('withdrawal address whitelist', () => {
  it('follows pending, confirmed, cooling down, then active', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();

    const add = await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS, label: 'Cold wallet' } });
    expect(add.status).toBe(201);
    expect(add.body.status).toBe('pending_confirmation');
    expect(h.mailer.sent).toHaveLength(1);
    expect(h.mailer.sent[0]).toMatchObject({ to: 'alice@example.com', network: 'ethereum' });
    expect(await allowed(h, accessToken)).toBe(false);

    const confirm = await h.call('POST', '/whitelist/confirm', { token: accessToken, body: { token: h.mailer.sent[0].token } });
    expect(confirm.status).toBe(200);
    expect(confirm.body.status).toBe('cooling_down');
    expect(await allowed(h, accessToken)).toBe(false);

    const activeAt = new Date(confirm.body.activeAt).getTime();
    const createdAt = new Date(confirm.body.createdAt).getTime();
    expect(activeAt - createdAt).toBeGreaterThanOrEqual(24 * 3600 * 1000 - 1000);

    await pool.query(`UPDATE whitelist_addresses SET active_at = now() - interval '1 minute'`);
    expect((await h.call('GET', '/whitelist', { token: accessToken })).body[0].status).toBe('active');
    expect(await allowed(h, accessToken)).toBe(true);
  });

  it('never lets an unconfirmed address become active, however old it is', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS } });
    await pool.query(`UPDATE whitelist_addresses SET active_at = now() - interval '30 days'`);
    expect(await allowed(h, accessToken)).toBe(false);
  });

  it('accepts a confirmation token once, and only from the owner', async () => {
    const h = makeApp(pool);
    const alice = await h.signIn('alice@example.com');
    const bob = await h.signIn('bob@example.com');
    await h.call('POST', '/whitelist', { token: alice.accessToken, body: { network: 'ethereum', address: ETH_ADDRESS } });
    const token = h.mailer.sent[0].token;

    expect((await h.call('POST', '/whitelist/confirm', { token: bob.accessToken, body: { token } })).status).toBe(400);
    expect((await h.call('POST', '/whitelist/confirm', { token: alice.accessToken, body: { token: 'z'.repeat(43) } })).status).toBe(400);
    expect((await h.call('POST', '/whitelist/confirm', { token: alice.accessToken, body: { token } })).status).toBe(200);
    expect((await h.call('POST', '/whitelist/confirm', { token: alice.accessToken, body: { token } })).status).toBe(400);
  });

  it('stores only a hash of the confirmation token', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS } });
    const stored = (await pool.query('SELECT confirm_token_hash FROM whitelist_addresses')).rows[0].confirm_token_hash;
    expect(stored).not.toBe(h.mailer.sent[0].token);
    expect(stored).toMatch(/^[0-9a-f]{64}$/);
  });

  it('removes an address immediately', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const add = await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS } });
    await h.call('POST', '/whitelist/confirm', { token: accessToken, body: { token: h.mailer.sent[0].token } });
    await pool.query(`UPDATE whitelist_addresses SET active_at = now() - interval '1 minute'`);
    expect(await allowed(h, accessToken)).toBe(true);

    expect((await h.call('DELETE', `/whitelist/${add.body.id}`, { token: accessToken })).status).toBe(204);
    expect(await allowed(h, accessToken)).toBe(false);
    expect((await h.call('DELETE', `/whitelist/${add.body.id}`, { token: accessToken })).status).toBe(404);
  });

  it('keeps users apart', async () => {
    const h = makeApp(pool);
    const alice = await h.signIn('alice@example.com');
    const bob = await h.signIn('bob@example.com');
    const add = await h.call('POST', '/whitelist', { token: alice.accessToken, body: { network: 'ethereum', address: ETH_ADDRESS } });
    expect((await h.call('GET', '/whitelist', { token: bob.accessToken })).body).toEqual([]);
    expect((await h.call('DELETE', `/whitelist/${add.body.id}`, { token: bob.accessToken })).status).toBe(404);
  });

  it('validates addresses, normalizes case, and blocks duplicates', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const bad = ['0x123', 'hello world 12345', '0xZZZZ8400098527886E0F7030069857D2E4169EE7'];
    for (const address of bad) {
      expect((await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address } })).status).toBe(400);
    }
    const ok = await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS } });
    expect(ok.body.address).toBe(ETH_ADDRESS.toLowerCase());
    const dup = await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS.toLowerCase() } });
    expect(dup.status).toBe(409);

    const btc = await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'bitcoin', address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq' } });
    expect(btc.status).toBe(201);
  });

  it('caps the number of addresses', async () => {
    const h = makeApp(pool, { whitelistMaxEntries: 2 });
    const { accessToken } = await h.signIn();
    const eth = (n: number) => `0x${n.toString(16).padStart(40, '0')}`;
    expect((await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: eth(1) } })).status).toBe(201);
    expect((await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: eth(2) } })).status).toBe(201);
    expect((await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: eth(3) } })).body.error.code).toBe('WHITELIST_FULL');
  });

  it('requires a second factor to add an address when 2FA is on', async () => {
    const h = makeApp(pool);
    const { accessToken } = await h.signIn();
    const { secret } = await h.enableTwoFactor(accessToken);

    const missing = await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS } });
    expect(missing.body.error.code).toBe('SECOND_FACTOR_REQUIRED');
    const wrong = await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS, code: '000000' } });
    expect(wrong.status).toBe(401);
    expect(h.mailer.sent).toHaveLength(0);

    const ok = await h.call('POST', '/whitelist', { token: accessToken, body: { network: 'ethereum', address: ETH_ADDRESS, code: currentCode(secret, 1) } });
    expect(ok.status).toBe(201);
  });

  it('requires authentication', async () => {
    const h = makeApp(pool);
    expect((await h.call('GET', '/whitelist')).status).toBe(401);
    expect((await h.call('POST', '/whitelist', { body: { network: 'ethereum', address: ETH_ADDRESS } })).status).toBe(401);
  });
});
