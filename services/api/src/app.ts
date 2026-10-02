/**
 * The API as two request handlers, bound to two ports:
 *
 *   public    what browsers reach: sign-in, the session, scans, the web app
 *   internal  what the worker reaches: the job queue; also /metrics
 *
 * The API never connects to a scan target. It checks a target's syntax,
 * queues a job, and stores whatever the worker reports (ADR 0008).
 */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { parseTarget, TargetRejected } from '@pq-oidc/scan-core/policy';
import { ENGINE_VERSION } from '@pq-oidc/scan-core/report';
import { Auth } from './auth.ts';
import type { SessionContext } from './auth.ts';
import type { ApiConfig } from './config.ts';
import { clientAddress, HttpError, readJson, redirect, requestIdFor, Router, sendError, sendJson, WindowLimiter } from './http.ts';
import type { Context } from './http.ts';
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

type Guard = 'public' | 'user' | 'user-write';
type Scan = Omit<ScanRow, 'result'> & { result?: string | null };

const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESULT_BYTES = 2 * 1024 * 1024;
const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString());

function parseJsonColumn(text: string | null | undefined): unknown {
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** A scan as its owner sees it. The full report is included only when asked for one scan. */
function presentScan(row: Scan, full: boolean) {
  return {
    id: row.id,
    kind: row.kind,
    target: row.input,
    targetUrl: row.targetUrl,
    status: row.status,
    createdAt: iso(row.createdAt),
    startedAt: iso(row.startedAt),
    finishedAt: iso(row.finishedAt),
    progress: row.progress ?? undefined,
    layers: parseJsonColumn(row.summary),
    error: row.errorCode ? { code: row.errorCode, message: row.errorMessage } : undefined,
    report: full ? parseJsonColumn(row.result) : undefined,
  };
}

export function createApi(options: ApiOptions) {
  const { config, store, log } = options;
  const now = options.now ?? Date.now;
  const auth = new Auth(config, store, now);
  const metrics = new Metrics();
  const serveStatic = config.webDir ? createStaticHandler(config.webDir) : undefined;
  const signInLimiter = new WindowLimiter(30, 60_000);

  const requests = metrics.counter('http_requests_total', 'Requests handled, by route and status.');
  const durations = metrics.histogram('http_request_duration_seconds', 'Time to handle a request.', [0.005, 0.025, 0.1, 0.5, 2.5]);
  const created = metrics.counter('scans_created_total', 'Scan jobs accepted.');
  const refused = metrics.counter('scans_refused_total', 'Scan requests refused, by reason.');
  const finished = metrics.counter('scan_jobs_finished_total', 'Scan jobs finished by a worker, by outcome.');
  const jobSeconds = metrics.histogram('scan_job_duration_seconds', 'Time from a job being claimed to its result.', [1, 2.5, 5, 10, 30, 60]);
  metrics.gauge('scan_jobs', 'Scan jobs in the database, by status.', () => store.countByStatus());

  // ---------------------------------------------------------------- public routes

  const routes = new Router<SessionContext | undefined>();
  const guards = new Map<string, Guard>();
  const route = (guard: Guard, method: 'GET' | 'POST' | 'DELETE', pattern: string, handler: (ctx: Context<SessionContext | undefined>) => Promise<void> | void) => {
    guards.set(`${method} ${pattern}`, guard);
    routes.on(method, pattern, handler);
  };
  /** For routes guarded by 'user' or 'user-write', the session is always there. */
  const user = (ctx: Context<SessionContext | undefined>) => ctx.session!;

  route('public', 'GET', '/healthz', ({ res }) => void res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok'));
  route('public', 'GET', '/readyz', ({ res }) => void res.writeHead(store.healthy() ? 200 : 503, { 'Content-Type': 'text/plain' }).end(store.healthy() ? 'ready' : 'database unavailable'));

  route('public', 'GET', '/api/v1/meta', ({ res }) =>
    sendJson(res, 200, {
      service: 'pq-oidc',
      engine: ENGINE_VERSION,
      signInUrl: '/auth/login',
      labOrigins: config.policy.labOrigins,
      allowedPorts: config.policy.allowedPorts,
      limits: { scansPerWindow: config.limits.scansPerWindow, windowSeconds: config.limits.windowMs / 1000, activePerUser: config.limits.activePerUser },
    }),
  );

  route('public', 'GET', '/auth/login', async ({ req, res, url }) => {
    const wait = signInLimiter.hit(clientAddress(req, options.trustProxy ?? false), now());
    if (wait > 0) throw new HttpError(429, 'rate-limited', 'Too many sign-in attempts. Try again shortly.', { 'Retry-After': String(wait) });
    const { location, setCookie } = await auth.startLogin(url.searchParams.get('return_to'));
    redirect(res, location, { 'Set-Cookie': setCookie });
  });

  route('public', 'GET', '/auth/callback', async ({ req, res, url, log: requestLog }) => {
    const { location, setCookie } = await auth.finishLogin(req, url, requestLog);
    redirect(res, location, { 'Set-Cookie': setCookie });
  });

  route('user-write', 'POST', '/auth/logout', async (ctx) => {
    const { setCookie, endSessionUrl } = await auth.logout(user(ctx));
    sendJson(ctx.res, 200, { endSessionUrl }, { 'Set-Cookie': setCookie });
  });

  route('public', 'GET', '/api/v1/session', ({ res, session }) => {
    if (!session) throw new HttpError(401, 'unauthenticated', 'Sign in to continue.');
    sendJson(res, 200, {
      user: { name: session.user.name, email: session.user.email, sub: session.user.sub },
      csrfToken: session.session.csrfToken,
      expiresAt: iso(session.session.expiresAt),
    });
  });

  // The ID token from the user's own sign-in, so they can put it through the token analyzer.
  route('user', 'GET', '/api/v1/session/id-token', (ctx) => sendJson(ctx.res, 200, { idToken: user(ctx).session.idToken }));

  route('user-write', 'POST', '/api/v1/scans', async (ctx) => {
    const { user: owner } = user(ctx);
    const body = await readJson(ctx.req, MAX_REQUEST_BYTES);
    const kind: JobKind = body.kind === 'issuer-keys' ? 'issuer-keys' : 'scan';
    if (typeof body.target !== 'string') throw new HttpError(400, 'invalid-request', 'Give the address to scan as "target".');

    let target;
    try {
      target = parseTarget(body.target, config.policy);
    } catch (error) {
      if (!(error instanceof TargetRejected)) throw error;
      refused.inc({ reason: error.code });
      ctx.log.info('scan target refused', { userId: owner.id, reason: error.code });
      throw new HttpError(422, error.code, error.message);
    }

    const at = now();
    const limit = (reason: string, status: number, message: string, retryAfter: number) => {
      refused.inc({ reason });
      throw new HttpError(status, reason, message, { 'Retry-After': String(retryAfter) });
    };
    const { limits } = config;
    if (store.countUserScansSince(owner.id, at - limits.windowMs) >= limits.scansPerWindow) {
      limit('rate-limited', 429, `You can start ${limits.scansPerWindow} scans every ${limits.windowMs / 60_000} minutes. Try again later.`, 60);
    }
    if (store.countUserActiveScans(owner.id) >= limits.activePerUser) {
      limit('too-many-active', 429, `You already have ${limits.activePerUser} scans in progress. Wait for one to finish.`, 10);
    }
    if (store.countHostScansSince(target.hostname, at - 60_000) >= limits.perHostPerMinute) {
      limit('host-busy', 429, `${target.hostname} was scanned moments ago. Use that result, or try again in a minute.`, 60);
    }
    if (store.queueDepth() >= limits.maxQueueDepth) limit('queue-full', 503, 'The scanner is busy. Try again shortly.', 30);

    const row = store.createScan({ id: randomUUID(), userId: owner.id, kind, input: body.target.trim().slice(0, 2048), targetUrl: target.url.href, targetHost: target.hostname }, at);
    created.inc({ kind });
    ctx.log.info('scan queued', { scanId: row.id, userId: owner.id, host: target.hostname, kind });
    sendJson(ctx.res, 202, { scan: presentScan(row, false) }, { Location: `/api/v1/scans/${row.id}` });
  });

  route('user', 'GET', '/api/v1/scans', (ctx) => {
    const limitParam = Number(ctx.url.searchParams.get('limit') ?? 25);
    const limit = Number.isInteger(limitParam) ? Math.min(Math.max(limitParam, 1), 100) : 25;
    const before = Date.parse(ctx.url.searchParams.get('before') ?? '');
    const rows = store.listScans(user(ctx).user.id, limit, Number.isNaN(before) ? undefined : before);
    sendJson(ctx.res, 200, { scans: rows.map((row) => presentScan(row, false)) });
  });

  /** One scan, if it belongs to the caller. Someone else's scan and a scan that does not exist look the same. */
  const ownScan = (ctx: Context<SessionContext | undefined>): ScanRow => {
    const row = store.getScan(user(ctx).user.id, ctx.params.id ?? '');
    if (!row) throw new HttpError(404, 'not-found', 'No such scan.');
    return row;
  };

  route('user', 'GET', '/api/v1/scans/:id', (ctx) => sendJson(ctx.res, 200, { scan: presentScan(ownScan(ctx), true) }));

  route('user-write', 'DELETE', '/api/v1/scans/:id', (ctx) => {
    const row = ownScan(ctx);
    store.deleteScan(row.userId, row.id);
    ctx.log.info('scan deleted', { scanId: row.id, userId: row.userId });
    ctx.res.writeHead(204).end();
  });

  // ---------------------------------------------------------------- internal routes

  const internal = new Router<undefined>();
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
      // The worker handles hostile input, so its output is data, not trusted structure.
      const result = body.result as { layers?: unknown };
      outcome = { result: JSON.stringify(result), summary: JSON.stringify(Array.isArray(result.layers) ? result.layers : []) };
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

  async function dispatch<S>(router: Router<S>, req: IncomingMessage, res: ServerResponse, prepare: (key: string, ctx: Context<S>) => void, fallback?: (pathname: string) => boolean) {
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
      const ctx = { req, res, url, params: matched.params, requestId, log: requestLog, session: undefined as S };
      prepare(`${method} ${pattern}`, ctx);
      await matched.route.handler(ctx);
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

  const handler = (req: IncomingMessage, res: ServerResponse) =>
    dispatch(
      routes,
      req,
      res,
      (key, ctx) => {
        const guard = guards.get(key) ?? 'user-write'; // a route with no declared guard gets the strictest one
        ctx.session = auth.sessionFor(req);
        if (guard === 'public') return;
        if (!ctx.session) throw new HttpError(401, 'unauthenticated', 'Sign in to continue.');
        if (guard === 'user-write') auth.requireSameSite(req, ctx.session);
      },
      serveStatic ? (pathname) => serveStatic(res, pathname) : undefined,
    );

  const internalHandler = (req: IncomingMessage, res: ServerResponse) =>
    dispatch(internal, req, res, (key) => {
      if (key === 'GET /healthz' || key === 'GET /metrics') return;
      if (!isWorker(req)) throw new HttpError(401, 'unauthenticated', 'A worker token is required.');
    });

  // Expired sessions and sign-in attempts are removed as time passes, not only when looked up.
  const sweeper = setInterval(() => store.sweep(now()), 10 * 60_000);
  sweeper.unref();

  return { handler, internalHandler, auth, metrics, close: () => clearInterval(sweeper) };
}
