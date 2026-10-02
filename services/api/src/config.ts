import { DEFAULT_POLICY, parseLabOrigins } from '@pq-oidc/scan-core/policy';
import type { TargetPolicy } from '@pq-oidc/scan-core/policy';

/**
 * The API's configuration, read once from environment variables and checked.
 * See .env.example for the full list.
 */
export interface ApiConfig {
  /** The URL people use to reach the app, e.g. http://localhost:8080. Requests from pages on other origins are refused. */
  publicUrl: string;
  /** Shared secret the worker presents on the internal port. */
  workerToken: string;
  databasePath: string;
  policy: TargetPolicy;
  limits: {
    /** Scans one visitor may start per window. */
    scansPerWindow: number;
    windowMs: number;
    /** Scans one visitor may have queued or running at once. */
    activePerClient: number;
    /** Scans of one host, by anyone, per minute. */
    perHostPerMinute: number;
    maxQueueDepth: number;
  };
  /** A second request for an address scanned this recently gets the existing result. */
  reuseMs: number;
  /** Results are deleted after this long. */
  retentionMs: number;
  /** Directory holding the built web app, if this server should serve it. */
  webDir?: string;
}

const DEMO_WORKER_TOKEN = 'demo-worker-token-change-me-0000000000';

function integer(env: NodeJS.ProcessEnv, name: string, fallback: number, min = 1): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min) throw new Error(`${name} must be an integer of at least ${min}`);
  return value;
}

export function configFromEnv(env: NodeJS.ProcessEnv): ApiConfig {
  const production = env.NODE_ENV === 'production';
  const publicUrl = (env.PUBLIC_URL ?? 'http://localhost:8080').replace(/\/$/, '');
  const workerToken = env.WORKER_TOKEN ?? (production ? '' : DEMO_WORKER_TOKEN);

  // The published demo value is for a laptop. Refuse to start a real deployment on it.
  if (workerToken.length < 32) throw new Error('WORKER_TOKEN is required and must be at least 32 characters');
  if (production && workerToken === DEMO_WORKER_TOKEN && env.ALLOW_DEMO_SECRETS !== 'true') {
    throw new Error('Refusing to start in production with the published demo worker token. Set WORKER_TOKEN.');
  }
  new URL(publicUrl); // throws on nonsense

  const ports = env.SCAN_ALLOWED_PORTS?.split(',').map((p) => Number(p.trim()));
  if (ports?.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) throw new Error('SCAN_ALLOWED_PORTS must be a comma-separated list of ports');

  return {
    publicUrl,
    workerToken,
    databasePath: env.DATABASE_PATH ?? 'data/scans.sqlite',
    policy: { allowedPorts: ports ?? DEFAULT_POLICY.allowedPorts, labOrigins: parseLabOrigins(env.SCAN_LAB_ORIGINS) },
    limits: {
      scansPerWindow: integer(env, 'RATE_LIMIT_SCANS', 20),
      windowMs: integer(env, 'RATE_LIMIT_WINDOW_SECONDS', 600) * 1000,
      activePerClient: integer(env, 'MAX_ACTIVE_SCANS_PER_CLIENT', 3),
      perHostPerMinute: integer(env, 'RATE_LIMIT_PER_HOST', 3),
      maxQueueDepth: integer(env, 'MAX_QUEUE_DEPTH', 100),
    },
    reuseMs: integer(env, 'REUSE_RESULT_SECONDS', 300, 0) * 1000,
    retentionMs: integer(env, 'RETENTION_HOURS', 1) * 3_600_000,
    webDir: env.WEB_DIR || undefined,
  };
}
