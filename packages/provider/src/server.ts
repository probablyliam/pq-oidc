import { createServer } from 'node:http';
import { createProviderApp } from './app.ts';
import { demoClientsFromEnv } from './clients.ts';
import { generateSigningKeys, loadSigningKeys } from './keys.ts';

/**
 * Starts the provider from environment variables. See .env.example for the full list.
 */
const env = process.env;
const port = Number(env.PORT ?? 3000);
const issuer = env.ISSUER ?? `http://localhost:${port}`;

const jwks = env.SIGNING_KEYS_JSON ? loadSigningKeys(env.SIGNING_KEYS_JSON) : await generateSigningKeys();
if (!env.SIGNING_KEYS_JSON) {
  console.log('No SIGNING_KEYS_JSON set: generated fresh in-memory signing keys (fine for a demo, not for production).');
}

const clients = demoClientsFromEnv(env);
const { handler } = createProviderApp({
  issuer,
  clients,
  jwks,
  cookieKeys: env.COOKIE_KEYS?.split(','),
  trustProxy: env.TRUST_PROXY === 'true',
});

const server = createServer(handler);
server.listen(port, () => {
  console.log(`Provider listening on ${issuer}`);
  for (const c of clients) console.log(`  ${c.clientId.padEnd(12)} → ID tokens signed with ${c.idTokenAlg}`);
});

// Kubernetes sends SIGTERM before stopping a pod: finish in-flight requests, then exit.
process.on('SIGTERM', () => server.close(() => process.exit(0)));
