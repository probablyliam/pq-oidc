import { useEffect, useState } from 'react';

/**
 * Hash routing: "#/lab?kex=hybrid". The site is served as static files, so the
 * server never has to know about routes.
 */
export interface Route {
  /** Path segments: "#/scans/abc" is ["scans", "abc"]. */
  path: string[];
  query: URLSearchParams;
}

export function parseHash(hash: string): Route {
  const [path = '', query = ''] = hash.replace(/^#\/?/, '').split('?');
  return { path: path.split('/').filter(Boolean).map(decodeURIComponent), query: new URLSearchParams(query) };
}

export function href(path: string, query?: Record<string, string | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) if (value !== undefined) params.set(key, value);
  const text = params.toString();
  return `#/${path}${text ? `?${text}` : ''}`;
}

export function navigate(path: string, query?: Record<string, string | undefined>) {
  window.location.hash = href(path, query);
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => {
      const next = parseHash(window.location.hash);
      setRoute((previous) => {
        // A new page starts at the top. A changed option on the same page stays where the reader is.
        if (previous.path.join('/') !== next.path.join('/')) window.scrollTo(0, 0);
        return next;
      });
    };
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}
