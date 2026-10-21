import { mkdir } from 'node:fs/promises';
import { buildServer } from './server.js';
import { loadOrCreateIdentity } from './signer.js';
import { openStore } from './store.js';

async function main(): Promise<void> {
  const dataDir = process.env.BRR_DATA_DIR ?? './data';
  const port = parseInt(process.env.PORT ?? '5000', 10);
  const host = process.env.HOST ?? '0.0.0.0';

  await mkdir(dataDir, { recursive: true });

  const store = await openStore();
  const identity = await loadOrCreateIdentity(dataDir);

  console.log(`[brr] service AID=${identity.aid}`);
  console.log('[brr] runtime=nodejs');

  const app = buildServer({ store, identity });

  const shutdown = async () => {
    await app.close();
    await store.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await app.listen({ port, host });
  console.log(`[brr] listening on http://${host}:${port}`);

  store.migrate().catch((err) => {
    console.error('[store] migration failed — shutting down:', err);
    process.exit(1);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});