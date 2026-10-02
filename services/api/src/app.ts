/**
 * The API as two request handlers, bound to two ports:
 *
 *   public    what browsers reach: start a scan, read a scan, the web app
 *   internal  what the worker reaches: the job queue; also /metrics
 *
 * There are no accounts (ADR 0014). Anyone can start a scan; what keeps that
 * from being abused is a limit per visitor address, a limit per target host,
 * and reusing a result when the same address was scanned moments ago.
 *
 * The API never connects to a scan target. It checks a target's syntax,
 * queues a job, and stores whatever the worker reports (ADR 0008).
 */
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { parseTarget, TargetRejected } from '@pq-oidc/scan-core/policy';
import { ENGINE_VERSION } from '@pq-oidc/scan-core/report';
import type { ApiConfig } from './config.ts';
import { clientAddress, HttpError, readJson, requestIdFor, Router, sendError, sendJson } from './http.ts';
import type { Logger } from './log.ts';
import { Metrics } from './metrics.ts';
import { createStaticHandler } from './static.ts';
import type { JobKind, ScanRow, Store } from './store.ts';

export interface ApiOptions {
  config: ApiConfig;
  store: Store;
  log: Logger;
  now?: () => number;
  /** Trust X-Forwarded-For for rate limiting (set behind a load balancer). */
  trustProxy?: boolean;
}

const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESULT_BYTES = 2 * 1024 * 1024;
const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString());

function parseJsonColumn(text: string | null): unknown {
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function presentScan(row: ScanRow) {
  return {
    id: row.id,
    kind: row.kind,
    target: row.input,
    targetUrl: row.targetUrl,
    status: row.status,
    createdAt: iso(row.createdAt),
    finishedAt: iso(row.finishedAt),
    progress: row.progress ?? undefined,
    error: row.errorCode ? { code: row.errorCode, message: row.errorMessage } : undefined,
    report: parseJsonColumn(row.result),
  };
}

export function createApi(options: ApiOptions) {
  const { config, store, log } = options;
  const now = options.now ?? Date.now;
  const metrics = new Metrics();
  const serveStatic = config.webDir ? createStaticHandler(config.webDir) : undefined;
  const publicOrigin = new URL(config.publicUrl).origin;

  // Visitors are counted by a keyed hash of their address. The key lives only in this process,
  // so the database never holds anything that can be turned back into an address.
  const clientKey = randomBytes(32);
  const clientOf = (req: IncomingMessage) => createHmac('sha256', clientKey).update(clientAddress(req, options.trustProxy ?? false)).digest('hex').slice(0, 32);

  const requests = metrics.counter('http_requests_total', 'Requests handled, by route and status.');
  const durations = metrics.histogram('http_request_duration_seconds', 'Time to handle a request.', [0.005, 0.025, 0.1, 0.5, 2.5]);
  const created = metrics.counter('scans_created_total', 'Scan jobs accepted.');
  const reused = metrics.counter('scans_reused_total', 'Requests answered with a result that already existed.');
  const refused = metrics.counter('scans_refused_total', 'Scan requests refused, by reason.');
  const finished = metrics.counter('scan_jobs_finished_total', 'Scan jobs finished by a worker, by outcome.');
  const jobSeconds = metrics.histogram('scan_job_duration_seconds', 'Time from a job being claimed to its result.', [1, 2.5, 5, 10, 30, 60]);
  metrics.gauge('scan_jobs', 'Scan jobs in the database, by status.', () => store.countByStatus());

  /**
   * A scan costs the target a dozen connections, so a page on another site
   * must not be able to make a visitor's browser start one. Browsers say
   * where a request came from; when they do, it has to be here. Scripts and
   * command-line clients send neither header and are held to the rate limits.
   */
  function requireSameOrigin(req: IncomingMessage) {
    const origin = req.headers.origin;
    const site = req.headers['sec-fetch-site'];
    if ((origin !== undefined && origin !== publicOrigin) || (site !== undefined && site !== 'same-origin' && site !== 'none')) {
      throw new HttpError(403, 'cross-site', 'Scans can only be started from this site.');
    }
  }

  // ---------------------------------------------------------------- public routes

  const routes = new Router();

  routes.on('GET', '/healthz', ({ res }) => void res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok'));
  routes.on('GET', '/readyz', ({ res }) => void res.writeHead(store.healthy() ? 200 : 503, { 'Content-Type': 'text/plain' }).end(store.healthy() ? 'ready' : 'database unavailable'));

  routes.on('GET', '/api/v1/meta', ({ res }) =>
    sendJson(res, 200, {
      service: 'pq-oidc',
      engine: ENGINE_VERSION,
      labOrigins: config.policy.labOrigins,
      allowedPorts: config.policy.allowedPorts,
      retentionHours: config.retentionMs / 3_600_000,
    }),
  );

  routes.on('POST', '/api/v1/scans', async (ctx) => {
    requireSameOrigin(ctx.req);
    const body = await readJson(ctx.req, MAX_REQUEST_BYTES);
    const kind: JobKind = body.kind === 'issuer-keys' ? 'issuer-keys' : 'scan';
    if (typeof body.target !== 'string') throw new HttpError(400, 'invalid-request', 'Give the address to scan as "target".');

    let target;
    try {
      target = parseTarget(body.target, config.policy);
    } catch (error) {
      if (!(error instanceof TargetRejected)) throw error;
      refused.inc({ reason: error.code });
      ctx.log.info('scan target refused', { reason: error.code });
      throw new HttpError(422, error.code, error.message);
    }

    const at = now();
    // Someone scanned exactly this a moment ago: hand back that scan instead of knocking on the target again.
    const existing = config.reuseMs > 0 ? store.findRecent(kind, target.url.href, at - config.reuseMs) : undefined;
    if (existing) {
      reused.inc({ kind });
      return sendJson(ctx.res, 200, { scan: presentScan(existing), reused: true });
    }

    const client = clientOf(ctx.req);
    const limit = (reason: string, status: number, message: string, retryAfter: number) => {
      refused.inc({ reason });
      throw new HttpError(status, reason, message, { 'Retry-After': String(retryAfter) });
    };
    const { limits } = config;
    if (store.countClientScansSince(client, at - limits.windowMs) >= limits.scansPerWindow) {
      limit('rate-limited', 429, `That is ${limits.scansPerWindow} scans in ${limits.windowMs / 60_000} minutes, which is the limit. Try again later.`, 60);
    }
    if (store.countClientActiveScans(client) >= limits.activePerClient) {
      limit('too-many-active', 429, `You already have ${limits.activePerClient} scans in progress. Wait for one to finish.`, 10);
    }
    // Per service, not per name: a host and port is one thing to protect, and local test servers share a name.
    const service = `${target.hostname}:${target.port}`;
    if (store.countHostScansSince(service, at - 60_000) >= limits.perHostPerMinute) {
      limit('host-busy', 429, `${service} has been scanned several times in the last minute. Try again in a minute.`, 60);
    }
    if (store.queueDepth() >= limits.maxQueueDepth) limit('queue-full', 503, 'The scanner is busy. Try again shortly.', 30);

    const row = store.createScan({ id: randomUUID(), client, kind, input: body.target.trim().slice(0, 2048), targetUrl: target.url.href, targetHost: service }, at);
    created.inc({ kind });
    ctx.log.info('scan queued', { scanId: row.id, host: target.hostname, kind });
    sendJson(ctx.res, 202, { scan: presentScan(row) }, { Location: `/api/v1/scans/${row.id}` });
  });

  // A scan's ID is its only key: 122 random bits. Whoever has the link can read the result until it expires.
  routes.on('GET', '/api/v1/scans/:id', (ctx) => {
    const row = store.getScan(ctx.params.id ?? '');
    if (!row) throw new HttpError(404, 'not-found', 'No such scan. Results are kept for a day.');
    sendJson(ctx.res, 200, { scan: presentScan(row) });
  });

  // ---------------------------------------------------------------- internal routes

  const internal = new Router();
  const workerId = (body: Record<string, unknown>): string => {
    if (typeof body.workerId !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(body.workerId)) throw new HttpError(400, 'invalid-request', 'workerId is required.');
    return body.workerId;
  };

  internal.on('GET', '/healthz', ({ res }) => void res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok'));
  internal.on('GET', '/metrics', ({ res }) => void res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' }).end(metrics.render()));

  internal.on('POST', '/internal/v1/jobs/claim', async ({ req, res, log: requestLog }) => {
    const job = store.claimJob(workerId(await readJson(req, MAX_REQUEST_BYTES)), now());
    if (!job) return void res.writeHead(204).end();
    requestLog.info('job claimed', { scanId: job.id, attempt: job.attempt });
    sendJson(res, 200, { job });
  });

  internal.on('POST', '/internal/v1/jobs/:id/progress', async ({ req, res, params }) => {
    const body = await readJson(req, MAX_REQUEST_BYTES);
    const step = typeof body.step === 'string' ? body.step.slice(0, 200) : '';
    // 409 tells the worker its lease is gone and it should stop.
    if (!store.reportProgress(params.id ?? '', workerId(body), step, now())) throw new HttpError(409, 'lease-lost', 'This worker no longer holds the job.');
    res.writeHead(204).end();
  });

  internal.on('POST', '/internal/v1/jobs/:id/result', async ({ req, res, params, log: requestLog }) => {
    const body = await readJson(req, MAX_RESULT_BYTES);
    const id = params.id ?? '';
    const worker = workerId(body);
    let outcome: Parameters<Store['finishJob']>[2];
    if (body.status === 'succeeded' && typeof body.result === 'object' && body.result !== null) {
      // The worker handles hostile input, so its output is stored as data and never interpreted here.
      outcome = { result: JSON.stringify(body.result) };
    } else if (body.status === 'failed' && typeof body.error === 'object' && body.error !== null) {
      const error = body.error as { code?: unknown; message?: unknown };
      outcome = { errorCode: String(error.code ?? 'failed').slice(0, 60), errorMessage: String(error.message ?? 'The scan failed.').slice(0, 500) };
    } else {
      throw new HttpError(400, 'invalid-request', 'A result needs status "succeeded" with a result, or "failed" with an error.');
    }
    if (!store.finishJob(id, worker, outcome, now())) throw new HttpError(409, 'lease-lost', 'This worker no longer holds the job.');
    const status = 'result' in outcome ? 'succeeded' : 'failed';
    finished.inc({ status, ...('errorCode' in outcome ? { code: outcome.errorCode } : {}) });
    if (typeof body.durationMs === 'number') jobSeconds.observe({ status }, body.durationMs / 1000);
    requestLog.info('job finished', { scanId: id, status, ...('errorCode' in outcome ? { code: outcome.errorCode } : {}) });
    res.writeHead(204).end();
  });

  // ---------------------------------------------------------------- dispatch

  const workerTokenHash = createHash('sha256').update(config.workerToken).digest();
  const isWorker = (req: IncomingMessage) => {
    const header = req.headers.authorization ?? '';
    const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
    return timingSafeEqual(createHash('sha256').update(presented).digest(), workerTokenHash);
  };

  async function dispatch(router: Router, req: IncomingMessage, res: ServerResponse, guard: (key: string) => void, fallback?: (pathname: string) => boolean) {
    const started = process.hrtime.bigint();
    const requestId = requestIdFor(req);
    const requestLog = log.child({ requestId });
    res.setHeader('X-Request-Id', requestId);
    let pattern = 'unmatched';
    try {
      const url = new URL(req.url ?? '/', config.publicUrl);
      const method = req.method ?? 'GET';
      const matched = router.match(method, url.pathname);
      if (matched === 'wrong-method') throw new HttpError(405, 'method-not-allowed', 'That method is not supported here.');
      if (!matched) {
        if (method === 'GET' && fallback?.(url.pathname)) return void (pattern = 'static');
        throw new HttpError(404, 'not-found', 'Not found.');
      }
      pattern = matched.route.pattern;
      guard(`${method} ${pattern}`);
      await matched.route.handler({ req, res, url, params: matched.params, requestId, log: requestLog });
    } catch (error) {
      if (res.headersSent) return void res.destroy();
      if (error instanceof HttpError) {
        sendError(res, error, requestId);
      } else {
        requestLog.error('request failed', { error, route: pattern });
        sendError(res, new HttpError(500, 'internal-error', 'Something went wrong on the server.'), requestId);
      }
    } finally {
      requests.inc({ method: req.method ?? 'GET', route: pattern, status: res.statusCode });
      durations.observe({ route: pattern }, Number(process.hrtime.bigint() - started) / 1e9);
    }
  }

  const handler = (req: IncomingMessage, res: ServerResponse) => dispatch(routes, req, res, () => {}, serveStatic ? (pathname) => serveStatic(res, pathname) : undefined);

  const internalHandler = (req: IncomingMessage, res: ServerResponse) =>
    dispatch(internal, req, res, (key) => {
      if (key === 'GET /healthz' || key === 'GET /metrics') return;
      if (!isWorker(req)) throw new HttpError(401, 'unauthenticated', 'A worker token is required.');
    });

  // Results are kept for a day and then deleted, whether or not anyone looks.
  const purge = () => {
    const removed = store.purge(now() - config.retentionMs);
    if (removed > 0) log.info('expired scans deleted', { removed });
  };
  const sweeper = setInterval(purge, 10 * 60_000);
  sweeper.unref();

  return { handler, internalHandler, metrics, purge, close: () => clearInterval(sweeper) };
}
