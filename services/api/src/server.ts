import { createServer } from 'node:http';
import { createApi } from './app.ts';
import { configFromEnv } from './config.ts';
import { createLogger } from './log.ts';
import type { LogLevel } from './log.ts';
import { Store } from './store.ts';

/**
 * Starts the API from environment variables. Two listeners:
 *   PORT           (8080) the public API and the web app
 *   INTERNAL_PORT  (8081) the worker's job queue and /metrics; keep it off the public network
 */
const env = process.env;
const log = createLogger({ service: 'api', level: (env.LOG_LEVEL as LogLevel | undefined) ?? 'info' });
const config = configFromEnv(env);
const store = new Store({ path: config.databasePath });
const api = createApi({ config, store, log, trustProxy: env.TRUST_PROXY === 'true' });

const host = env.HOST ?? '127.0.0.1';
const port = Number(env.PORT ?? 8080);
const internalPort = Number(env.INTERNAL_PORT ?? 8081);

const server = createServer(api.handler);
const internal = createServer(api.internalHandler);
server.listen(port, host, () => log.info('listening', { url: config.publicUrl, host, port }));
internal.listen(internalPort, env.INTERNAL_HOST ?? host, () => log.info('internal listener ready', { port: internalPort }));

if (config.policy.labOrigins.length > 0) {
  // Loud on purpose: these origins bypass the address rules. They belong on a developer's machine only.
  log.warn('SCAN_LAB_ORIGINS is set: these origins are exempt from the scanner address and port rules', { labOrigins: config.policy.labOrigins });
}
if (!(await api.auth.providerAvailable())) {
  log.warn('the identity provider is not reachable yet; sign-in will work once it is', { issuer: config.oidc.issuer });
}

// Kubernetes sends SIGTERM before stopping a pod: finish in-flight requests, then exit.
function shutdown() {
  api.close();
  internal.close();
  server.close(() => {
    store.close();
    process.exit(0);
  });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
