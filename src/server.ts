import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { createPool } from './db.js';
import { ConsoleMailer } from './mailer.js';
import { migrate } from './migrate.js';

const config = loadConfig();
await migrate(config.databaseUrl);
const pool = createPool(config.databaseUrl);
const app = buildApp({ pool, config, mailer: new ConsoleMailer() });

const shutdown = async () => {
  await app.close();
  await pool.end();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await app.listen({ port: config.port, host: '0.0.0.0' });
console.log(`phantom-auth listening on :${config.port}`);
