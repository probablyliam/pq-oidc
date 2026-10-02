/**
 * HTTP GET for the scanner. Every request goes to a pinned address (ADR 0007):
 * the host name is used for SNI and the Host header only. Redirects are never
 * followed by the HTTP client; each Location is parsed, checked and resolved
 * again as if a user had typed it.
 *
 * TLS here is Node's (OpenSSL). The certificate is not required to be valid,
 * because a scanner wants to look at broken sites too, but whether it
 * validated is recorded. No credentials, cookies or request bodies are sent.
 */
import http from 'node:http';
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import { ConnectError } from '../net/connect.ts';
import { parseTarget, TargetRejected } from '../net/policy.ts';
import type { Target, TargetPolicy } from '../net/policy.ts';
import { resolveTarget } from '../net/resolve.ts';
import type { Lookup, PinnedTarget } from '../net/resolve.ts';
import type { HttpHop } from '../report.ts';

export const USER_AGENT = 'pq-oidc-scanner/1.0 (+https://github.com/probablyliam/pq-oidc)';

export interface HttpResponse {
  url: string;
  status: number;
  headers: http.IncomingHttpHeaders;
  /** At most `maxBytes` of the body. */
  body: Buffer;
  truncated: boolean;
  /** Present for https: did Node's TLS stack accept the certificate chain and host name? */
  tls?: { authorized: boolean; authorizationError?: string };
}

export interface FetchOptions {
  /** Longest one exchange may take. */
  timeoutMs?: number;
  maxBytes?: number;
  /** Epoch milliseconds after which the scan as a whole is out of time. */
  deadline?: number;
}

/** Every group Node's OpenSSL can negotiate, so this connection succeeds wherever one of the scanner's own handshakes did. */
const NODE_TLS_GROUPS = 'X25519MLKEM768:X25519:P-256:P-384:SecP256r1MLKEM768:SecP384r1MLKEM1024:MLKEM768:MLKEM1024';

/** A request that did not produce an HTTP response. */
export class FetchError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'FetchError';
    this.code = code;
  }
}

export function fetchPinned(url: URL, pinned: PinnedTarget, options: FetchOptions = {}): Promise<HttpResponse> {
  const timeoutMs = Math.min(options.timeoutMs ?? 8000, (options.deadline ?? Infinity) - Date.now());
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const secure = url.protocol === 'https:';
  if (timeoutMs <= 0) return Promise.reject(new FetchError('timeout', 'The scan ran out of time before this request.'));

  return new Promise<HttpResponse>((resolve, reject) => {
    const request = (secure ? https : http).request({
      host: pinned.address,
      family: pinned.family,
      port: pinned.port,
      // SNI and certificate name check use the host name; an IP target sends no SNI.
      servername: secure && pinned.hasHostname ? pinned.hostname : undefined,
      path: `${url.pathname}${url.search}`,
      method: 'GET',
      headers: { host: url.host, 'user-agent': USER_AGENT, accept: 'text/html,application/json;q=0.9,*/*;q=0.5', 'accept-encoding': 'identity', connection: 'close' },
      agent: false,
      rejectUnauthorized: false,
      ecdhCurve: NODE_TLS_GROUPS,
      lookup: () => {
        throw new ConnectError('not-pinned', 'Unexpected DNS lookup for a pinned target.');
      },
    });

    let settled = false;
    const fail = (code: string, message: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      request.destroy();
      reject(new FetchError(code, message));
    };
    const deadline = setTimeout(() => fail('timeout', `No complete response from ${url.host} within ${timeoutMs} ms.`), timeoutMs);

    request.on('error', (error: NodeJS.ErrnoException) => fail(error.code ?? 'network', `Request to ${url.host} failed: ${error.message}`));
    request.on('response', (response) => {
      const socket = response.socket as TLSSocket;
      const tls = secure ? { authorized: socket.authorized, authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined } : undefined;
      const chunks: Buffer[] = [];
      let size = 0;
      const done = (truncated: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        request.destroy();
        resolve({ url: url.href, status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks), truncated, tls });
      };
      response.on('data', (chunk: Buffer) => {
        const room = maxBytes - size;
        if (chunk.length >= room) {
          chunks.push(chunk.subarray(0, room));
          size = maxBytes;
          done(true); // stop reading: a scanner has no use for the rest
        } else {
          chunks.push(chunk);
          size += chunk.length;
        }
      });
      response.on('end', () => done(false));
      response.on('error', (error) => fail('network', `Reading from ${url.host} failed: ${error.message}`));
    });
    request.end();
  });
}

export interface FollowOptions extends FetchOptions {
  lookup?: Lookup;
  maxRedirects?: number;
}

export interface FollowResult {
  hops: HttpHop[];
  /** Every response received, in order; the last one is where the chain ended. */
  responses: { target: Target; pinned: PinnedTarget; response: HttpResponse }[];
  blockedRedirect?: { location: string; code: string; reason: string };
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

/**
 * GETs `start` and follows redirects by hand. A redirect to a new origin is
 * treated exactly like a new target: parsed against the policy, resolved once,
 * every address checked, then pinned. Anything refused ends the chain and is
 * reported, never fetched.
 */
export async function fetchFollowingRedirects(start: Target, startPinned: PinnedTarget, policy: TargetPolicy, options: FollowOptions = {}): Promise<FollowResult> {
  const maxRedirects = options.maxRedirects ?? 5;
  const pins = new Map<string, PinnedTarget>([[start.origin, startPinned]]);
  const result: FollowResult = { hops: [], responses: [] };
  let target = start;

  for (let hop = 0; ; hop++) {
    const pinned = pins.get(target.origin)!;
    let response: HttpResponse;
    try {
      response = await fetchPinned(target.url, pinned, options);
    } catch (error) {
      if (!(error instanceof FetchError)) throw error;
      result.hops.push({ url: target.url.href, error: error.message });
      return result;
    }
    result.responses.push({ target, pinned, response });
    const location = REDIRECTS.has(response.status) ? response.headers.location : undefined;
    result.hops.push({ url: target.url.href, status: response.status, location });
    if (!location) return result;

    if (hop >= maxRedirects) {
      result.blockedRedirect = { location, code: 'too-many-redirects', reason: `Stopped after ${maxRedirects} redirects.` };
      return result;
    }
    try {
      const next = parseTarget(new URL(location, target.url).href, policy);
      if (!pins.has(next.origin)) pins.set(next.origin, await resolveTarget(next, { lookup: options.lookup }));
      target = next;
    } catch (error) {
      if (!(error instanceof TargetRejected) && !(error instanceof TypeError)) throw error;
      const code = error instanceof TargetRejected ? error.code : 'invalid-url';
      result.blockedRedirect = { location, code, reason: error.message };
      return result;
    }
  }
}
