/**
 * Serves the built web app from the same origin as the API, so the session
 * cookie needs no cross-origin arrangement and there is no CORS to configure.
 */
import { createReadStream, statSync } from 'node:fs';
import type { ServerResponse } from 'node:http';
import { extname, join, normalize, resolve, sep } from 'node:path';

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

/**
 * The page may load scripts, styles, fonts and images from this origin only,
 * and may be framed by nobody. `connect-src` also allows https: because the
 * token page fetches an issuer's public keys straight from the issuer.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' https:",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export function createStaticHandler(webDir: string) {
  const root = resolve(webDir);

  /** Sends the file for `pathname` if there is one. Returns false if not, so the caller can answer 404. */
  return function serve(res: ServerResponse, pathname: string): boolean {
    let relative: string;
    try {
      relative = normalize(decodeURIComponent(pathname));
    } catch {
      return false;
    }
    let file = join(root, relative);
    // Whatever the path contained, the file must be inside the web directory.
    if (file !== root && !file.startsWith(root + sep)) return false;
    try {
      if (statSync(file).isDirectory()) file = join(file, 'index.html');
      const stats = statSync(file);
      if (!stats.isFile()) return false;
      const type = TYPES[extname(file)] ?? 'application/octet-stream';
      const html = type.startsWith('text/html');
      res.writeHead(200, {
        'Content-Type': type,
        'Content-Length': stats.size,
        // Vite puts a content hash in asset file names, so those never change; the page that names them must be re-checked.
        'Cache-Control': relative.includes(`${sep}assets${sep}`) ? 'public, max-age=31536000, immutable' : 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        ...(html ? { 'Content-Security-Policy': CONTENT_SECURITY_POLICY } : {}),
      });
      createReadStream(file).pipe(res);
      return true;
    } catch {
      return false;
    }
  };
}
