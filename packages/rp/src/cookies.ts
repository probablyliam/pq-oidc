import type { IncomingMessage } from 'node:http';

export function readCookies(req: IncomingMessage): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const index = part.indexOf('=');
    if (index > 0) cookies.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }
  return cookies;
}

export interface CookieOptions {
  maxAgeSeconds?: number;
  secure: boolean;
}

/**
 * HttpOnly: page scripts can't read it (limits XSS damage).
 * SameSite=Lax: sent on top-level navigations (so the login redirect works) but not on cross-site subrequests.
 */
export function serializeCookie(name: string, value: string, { maxAgeSeconds, secure }: CookieOptions): string {
  const parts = [`${name}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (maxAgeSeconds !== undefined) parts.push(`Max-Age=${maxAgeSeconds}`);
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

export function clearCookie(name: string, secure: boolean): string {
  return serializeCookie(name, '', { maxAgeSeconds: 0, secure });
}
