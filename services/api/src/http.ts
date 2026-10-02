/**
 * The HTTP plumbing the API needs and no more: a router, JSON in and out with
 * a size cap, and one error type that decides what a client is told.
 * The existing services use node:http directly; this keeps to that.
 */
import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Logger } from './log.ts';

/** An error whose message is safe to show to the caller. Anything else becomes a 500 with no detail. */
export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly headers: Record<string, string>;

  constructor(status: number, code: string, message: string, headers: Record<string, string> = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

export interface Context {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: Record<string, string>;
  requestId: string;
  log: Logger;
}

export type Handler = (ctx: Context) => Promise<void> | void;

interface Route {
  method: string;
  /** For metrics: the pattern, not the path, so scan IDs do not become label values. */
  pattern: string;
  regex: RegExp;
  names: string[];
  handler: Handler;
}

export class Router {
  private readonly routes: Route[] = [];

  /** Registers a route. `pattern` may contain `:name` segments, e.g. /api/v1/scans/:id. */
  on(method: 'GET' | 'POST', pattern: string, handler: Handler): this {
    const names: string[] = [];
    const regex = new RegExp(`^${pattern.replace(/:([a-z]+)/gi, (_, name: string) => (names.push(name), '([^/]+)'))}$`);
    this.routes.push({ method, pattern, regex, names, handler });
    return this;
  }

  match(method: string, pathname: string): { route: Route; params: Record<string, string> } | 'wrong-method' | undefined {
    let pathMatched = false;
    for (const route of this.routes) {
      const found = route.regex.exec(pathname);
      if (!found) continue;
      pathMatched = true;
      if (route.method !== method) continue;
      const params: Record<string, string> = {};
      route.names.forEach((name, i) => (params[name] = decodeURIComponent(found[i + 1]!)));
      return { route, params };
    }
    return pathMatched ? 'wrong-method' : undefined;
  }
}

const SAFE_REQUEST_ID = /^[A-Za-z0-9._-]{8,64}$/;

/** Uses the caller's X-Request-Id when it is harmless to echo into logs and headers, otherwise makes one. */
export function requestIdFor(req: IncomingMessage): string {
  const supplied = req.headers['x-request-id'];
  return typeof supplied === 'string' && SAFE_REQUEST_ID.test(supplied) ? supplied : randomUUID();
}

const API_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string | string[]> = {}) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text), ...API_HEADERS, ...headers });
  res.end(text);
}

export function sendError(res: ServerResponse, error: HttpError, requestId: string) {
  sendJson(res, error.status, { error: { code: error.code, message: error.message, requestId } }, error.headers);
}

/**
 * Reads a JSON object from the request body. The content type must be JSON,
 * which a cross-site form cannot send, and the body is capped.
 */
export async function readJson(req: IncomingMessage, maxBytes: number): Promise<Record<string, unknown>> {
  if (!String(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
    throw new HttpError(415, 'unsupported-media-type', 'Send the request body as application/json.');
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > maxBytes) throw new HttpError(413, 'body-too-large', `The request body is larger than ${maxBytes} bytes.`);
    chunks.push(chunk);
  }
  let value: unknown;
  try {
    value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'invalid-json', 'The request body is not valid JSON.');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new HttpError(400, 'invalid-json', 'The request body must be a JSON object.');
  return value as Record<string, unknown>;
}

/** The client's address, for rate limiting. Trusts X-Forwarded-For only when told the server is behind a proxy. */
export function clientAddress(req: IncomingMessage, trustProxy: boolean): string {
  const forwarded = trustProxy ? String(req.headers['x-forwarded-for'] ?? '').split(',')[0]?.trim() : '';
  return forwarded || req.socket.remoteAddress || 'unknown';
}
