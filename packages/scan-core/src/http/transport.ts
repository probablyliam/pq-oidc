/**
 * The HTTP-level facts that decide whether the TLS underneath is actually
 * used: does the site force HTTPS, and are its cookies restricted to it?
 * A strong key exchange protects nothing for a visitor who was left on HTTP.
 *
 * Deliberately not a header linter: CSP, framing and the rest are application
 * security, not cryptographic posture.
 */
import net from 'node:net';
import type { PinnedTarget } from '../net/resolve.ts';
import type { CookieSummary, TransportSummary } from '../report.ts';
import { USER_AGENT } from './fetch.ts';
import type { FollowResult } from './fetch.ts';

export function parseHsts(value: string): NonNullable<TransportSummary['hsts']> {
  const directives = value.split(';').map((d) => d.trim().toLowerCase());
  const maxAge = directives.map((d) => /^max-age\s*=\s*"?(\d+)"?$/.exec(d)?.[1]).find(Boolean);
  return {
    raw: value,
    maxAge: maxAge === undefined ? undefined : Number(maxAge),
    includeSubDomains: directives.includes('includesubdomains'),
    preload: directives.includes('preload'),
  };
}

/** Name and flags only. Cookie values are never kept: they may be someone's session. */
export function parseSetCookie(header: string): CookieSummary {
  const [pair = '', ...attributes] = header.split(';');
  const flags = attributes.map((a) => a.trim().toLowerCase());
  return {
    name: pair.slice(0, Math.max(0, pair.indexOf('='))).trim() || '(unnamed)',
    secure: flags.includes('secure'),
    httpOnly: flags.includes('httponly'),
    sameSite: flags.find((f) => f.startsWith('samesite='))?.slice('samesite='.length),
  };
}

export function summarizeTransport(follow: FollowResult, targetOrigin: string, plainHttp: TransportSummary['plainHttp']): TransportSummary {
  // Only what the scanned origin itself sent; other origins in the redirect chain have their own policy.
  const own = follow.responses.filter((r) => r.target.origin === targetOrigin).map((r) => r.response);
  const hstsHeader = own.map((r) => r.headers['strict-transport-security']).find((h): h is string => typeof h === 'string');
  const cookies = new Map<string, CookieSummary>();
  for (const response of own) {
    for (const header of response.headers['set-cookie'] ?? []) {
      const cookie = parseSetCookie(header);
      cookies.set(cookie.name, cookie);
    }
  }
  const server = own[0]?.headers.server;
  return {
    hops: follow.hops,
    blockedRedirect: follow.blockedRedirect,
    hsts: hstsHeader ? parseHsts(hstsHeader) : undefined,
    cookies: [...cookies.values()],
    plainHttp,
    serverHeader: typeof server === 'string' ? server.slice(0, 120) : undefined,
  };
}

/**
 * Asks port 80 on the already-validated address what it does with plain HTTP.
 * The request line and headers are fixed; only the status line and Location
 * header of the answer are read.
 */
export function checkPlainHttp(pinned: PinnedTarget, timeoutMs = 4000): Promise<NonNullable<TransportSummary['plainHttp']>> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: pinned.address, family: pinned.family, port: 80 });
    let data = '';
    const finish = (result: NonNullable<TransportSummary['plainHttp']>) => {
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => finish({ upgradesToHttps: false, error: 'no answer on port 80' }), timeoutMs);
    socket.on('error', (error: NodeJS.ErrnoException) =>
      finish({ upgradesToHttps: false, error: error.code === 'ECONNREFUSED' ? 'port 80 is closed' : `port 80: ${error.message}` }),
    );
    socket.on('connect', () => {
      const host = pinned.family === 6 && !pinned.hasHostname ? `[${pinned.hostname}]` : pinned.hostname;
      socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
    });
    const parse = () => {
      const head = data.split('\r\n\r\n')[0] ?? '';
      const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(head)?.[1]);
      if (!status) return finish({ upgradesToHttps: false, error: 'port 80 did not answer with HTTP' });
      const location = /^location:\s*(.+)$/im.exec(head)?.[1]?.trim();
      finish({ status, location, upgradesToHttps: status >= 300 && status < 400 && Boolean(location?.toLowerCase().startsWith('https://')) });
    };
    socket.on('data', (chunk: Buffer) => {
      data += chunk.toString('latin1');
      if (data.includes('\r\n\r\n') || data.length > 16 * 1024) parse();
    });
    socket.on('end', parse);
  });
}
