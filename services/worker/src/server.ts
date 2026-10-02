import { hostname } from 'node:os';
import { DEFAULT_POLICY, parseLabOrigins } from '@pq-oidc/scan-core';
import { startWorker } from './worker.ts';
import type { WorkerLog } from './worker.ts';

/** Starts a worker from environment variables. See .env.example. */
const env = process.env;
const token = env.WORKER_TOKEN ?? (env.NODE_ENV === 'production' ? '' : 'demo-worker-token-change-me-0000000000');
if (token.length < 32) throw new Error('WORKER_TOKEN is required and must be at least 32 characters');

const labOrigins = parseLabOrigins(env.SCAN_LAB_ORIGINS);
const ports = env.SCAN_ALLOWED_PORTS?.split(',').map((p) => Number(p.trim()));
const workerId = `${hostname()}-${process.pid}`.replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 80);

const log: WorkerLog = (level, message, fields = {}) => {
  process.stdout.write(`${JSON.stringify({ time: new Date().toISOString(), level, service: 'worker', workerId, message, ...fields })}\n`);
};

if (labOrigins.length > 0) log('warn', 'SCAN_LAB_ORIGINS is set: these origins are exempt from the scanner address and port rules', { labOrigins });

const worker = startWorker({
  apiUrl: (env.API_INTERNAL_URL ?? 'http://127.0.0.1:8081').replace(/\/$/, ''),
  token,
  workerId,
  policy: { allowedPorts: ports ?? DEFAULT_POLICY.allowedPorts, labOrigins },
  concurrency: Number(env.WORKER_CONCURRENCY ?? 2),
  log,
});
log('info', 'worker started');

// Finish the scans in flight before exiting, so a rolling update does not fail them.
async function shutdown() {
  log('info', 'stopping after in-flight scans');
  await worker.stop();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
