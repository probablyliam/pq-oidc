/**
 * The scanner as one Vercel Function (ADR 0016). A scan runs inside the
 * request and its progress is streamed back as newline-delimited JSON:
 *
 *   {"progress":"Resolving example.com"}     as each step starts
 *   {"scan":{...}}                            once, at the end
 *
 * Refusals (a bad address, a limit) are plain JSON with the HTTP status that
 * says why, sent before anything is streamed. There is no database: a result
 * exists only in the response. The limits are kept in the memory of the
 * function instance, which Vercel shares between concurrent requests and
 * keeps warm, so they hold for the common case and are not a hard guarantee.
 *
 * This file is bundled to api/v1/scan.js (npm run vercel:bundle) so that the
 * deployed function is a single plain-JavaScript file with no workspace
 * imports for Vercel's build to resolve.
 */
import { DEFAULT_POLICY, ENGINE_VERSION, fetchIssuerKeys, parseTarget, runScan, TargetRejected } from '@pq-oidc/scan-core';
import type { IssuerKeys, ScanReport } from '@pq-oidc/scan-core';

export { ENGINE_VERSION };
export const config = { maxDuration: 60 };

/** Limits, per visitor and per scanned service. The same numbers as the self-hosted API's defaults. */
export const LIMITS = {
  scansPerWindow: 20,
  windowMs: 600_000,
  activePerClient: 3,
  perHostPerMinute: 3,
  /** Scans running at once in this instance. */
  maxActive: 12,
  /** A repeat of the same address within this window is answered with the earlier result. */
  reuseMs: 300_000,
  /** The whole scan, including finding the login; well inside the function's maxDuration. */
  budgetMs: 45_000,
};

type Kind = 'scan' | 'issuer-keys';
interface Finished {
  kind: Kind;
  target: string;
  targetUrl: string;
  status: 'succeeded' | 'failed';
  createdAt: string;
  finishedAt: string;
  error?: { code: string; message: string };
  report?: ScanReport | IssuerKeys;
}

/** What one instance remembers. Exported so tests can reset it. */
export const memory = {
  byClient: new Map<string, number[]>(),
  activeByClient: new Map<string, number>(),
  byService: new Map<string, number[]>(),
  recent: new Map<string, { at: number; scan: Finished }>(),
  active: 0,
  reset() {
    this.byClient.clear();
    this.activeByClient.clear();
    this.byService.clear();
    this.recent.clear();
    this.active = 0;
  },
};

class Refusal extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfter?: number;
  constructor(status: number, code: string, message: string, retryAfter?: number) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });

/** Vercel puts the visitor's address first in x-forwarded-for; there is no proxy of ours in front. */
function clientOf(request: Request): string {
  const forwarded = request.headers.get('x-forwarded-for') ?? '';
  return forwarded.split(',')[0]!.trim() || request.headers.get('x-real-ip') || 'unknown';
}

/** Scans can only be started from the site itself: a page elsewhere must not spend a visitor's allowance or use them as a relay. */
function requireSameOrigin(request: Request) {
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? '';
  const origin = request.headers.get('origin');
  const site = request.headers.get('sec-fetch-site');
  const ours = origin === null || origin === `https://${host}` || origin === `http://${host}`;
  if (!ours || (site !== null && site !== 'same-origin' && site !== 'none')) throw new Refusal(403, 'cross-site', 'Scans can only be started from this site.');
}

/** Drops timestamps older than `windowMs` and returns how many remain. */
function recent(map: Map<string, number[]>, key: string, now: number, windowMs: number): number[] {
  const kept = (map.get(key) ?? []).filter((t) => now - t < windowMs);
  map.set(key, kept);
  return kept;
}

/** Trims the memory maps so a long-lived instance does not grow without bound. */
function sweep(now: number) {
  for (const [key, times] of memory.byClient) if (times.every((t) => now - t >= LIMITS.windowMs)) memory.byClient.delete(key);
  for (const [key, times] of memory.byService) if (times.every((t) => now - t >= 60_000)) memory.byService.delete(key);
  for (const [key, entry] of memory.recent) if (now - entry.at >= LIMITS.reuseMs) memory.recent.delete(key);
}

export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST') return json(405, { error: { code: 'method-not-allowed', message: 'POST a JSON body with "target".' } }, { allow: 'POST' });
    try {
      requireSameOrigin(request);
      if (!/^application\/json\b/.test(request.headers.get('content-type') ?? '')) throw new Refusal(415, 'invalid-request', 'Send JSON.');
      const text = await request.text();
      if (text.length > 4096) throw new Refusal(413, 'invalid-request', 'The request is too large.');
      let body: { target?: unknown; kind?: unknown };
      try {
        body = JSON.parse(text) as typeof body;
      } catch {
        throw new Refusal(400, 'invalid-request', 'The body is not JSON.');
      }
      if (typeof body.target !== 'string') throw new Refusal(400, 'invalid-request', 'Give the address to scan as "target".');
      const kind: Kind = body.kind === 'issuer-keys' ? 'issuer-keys' : 'scan';
      const input = body.target.trim().slice(0, 2048);

      let target;
      try {
        target = parseTarget(input, DEFAULT_POLICY);
      } catch (error) {
        if (!(error instanceof TargetRejected)) throw error;
        throw new Refusal(422, error.code, error.message);
      }

      const now = Date.now();
      sweep(now);
      const reuseKey = `${kind} ${target.url.href}`;
      const earlier = memory.recent.get(reuseKey);
      if (earlier && now - earlier.at < LIMITS.reuseMs) return json(200, { scan: earlier.scan, reused: true });

      const client = clientOf(request);
      const service = `${target.hostname}:${target.port}`;
      if (recent(memory.byClient, client, now, LIMITS.windowMs).length >= LIMITS.scansPerWindow) {
        throw new Refusal(429, 'rate-limited', `That is ${LIMITS.scansPerWindow} scans in ${LIMITS.windowMs / 60_000} minutes, which is the limit. Try again later.`, 60);
      }
      if ((memory.activeByClient.get(client) ?? 0) >= LIMITS.activePerClient) throw new Refusal(429, 'too-many-active', `You already have ${LIMITS.activePerClient} scans in progress. Wait for one to finish.`, 10);
      if (recent(memory.byService, service, now, 60_000).length >= LIMITS.perHostPerMinute) {
        throw new Refusal(429, 'host-busy', `${service} has been scanned several times in the last minute. Try again in a minute.`, 60);
      }
      if (memory.active >= LIMITS.maxActive) throw new Refusal(503, 'queue-full', 'The scanner is busy. Try again shortly.', 30);

      memory.byClient.get(client)!.push(now);
      memory.byService.get(service)!.push(now);
      memory.activeByClient.set(client, (memory.activeByClient.get(client) ?? 0) + 1);
      memory.active++;

      const encoder = new TextEncoder();
      const stream = new ReadableStream<Uint8Array>({
        async start(controller) {
          const line = (value: unknown) => controller.enqueue(encoder.encode(`${JSON.stringify(value)}\n`));
          const createdAt = new Date(now).toISOString();
          let finished: Finished;
          try {
            const report =
              kind === 'issuer-keys'
                ? await fetchIssuerKeys(input, { policy: DEFAULT_POLICY, budgetMs: LIMITS.budgetMs })
                : await runScan(input, { policy: DEFAULT_POLICY, budgetMs: LIMITS.budgetMs, onProgress: (step) => line({ progress: step }) });
            finished = { kind, target: input, targetUrl: target.url.href, status: 'succeeded', createdAt, finishedAt: new Date().toISOString(), report };
            memory.recent.set(reuseKey, { at: Date.now(), scan: finished });
          } catch (error) {
            const refused = error instanceof TargetRejected;
            finished = {
              kind,
              target: input,
              targetUrl: target.url.href,
              status: 'failed',
              createdAt,
              finishedAt: new Date().toISOString(),
              error: refused ? { code: error.code, message: error.message } : { code: 'scanner-error', message: 'The scan failed. Try again, or try the login page’s own address.' },
            };
            if (!refused) console.error('scan failed', { target: target.hostname, error: error instanceof Error ? error.message : String(error) });
          } finally {
            memory.active--;
            memory.activeByClient.set(client, Math.max(0, (memory.activeByClient.get(client) ?? 1) - 1));
          }
          line({ scan: finished });
          controller.close();
        },
      });
      return new Response(stream, { status: 200, headers: { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store', 'x-engine': ENGINE_VERSION } });
    } catch (error) {
      if (error instanceof Refusal) {
        return json(error.status, { error: { code: error.code, message: error.message } }, error.retryAfter ? { 'retry-after': String(error.retryAfter) } : {});
      }
      console.error('request failed', error);
      return json(500, { error: { code: 'internal', message: 'Something went wrong.' } });
    }
  },
};
