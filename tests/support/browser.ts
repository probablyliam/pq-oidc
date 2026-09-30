/**
 * A tiny scripted browser for tests: follows redirects and keeps cookies the
 * way a real browser does, including the part this project is about:
 * cookies larger than 4096 bytes are silently dropped.
 *
 * Like browsers, cookies are scoped by hostname (not port), so apps on
 * localhost:3001 and localhost:3002 share one cookie jar.
 */
const BROWSER_COOKIE_LIMIT = 4096;
const MAX_REDIRECTS = 15;

export interface Page {
  status: number;
  url: string;
  body: string;
  headers: Headers;
}

export interface NavigateOptions {
  method?: 'GET' | 'POST';
  form?: Record<string, string>;
  /** Stop following redirects when the next URL matches (returns the redirect itself). */
  stopWhen?: (nextUrl: URL) => boolean;
}

export class TestBrowser {
  readonly jar = new Map<string, Map<string, string>>();
  readonly droppedCookies: string[] = [];

  async navigate(startUrl: string, options: NavigateOptions = {}): Promise<Page> {
    let url = new URL(startUrl);
    let method = options.method ?? 'GET';
    let body: string | undefined = options.form ? new URLSearchParams(options.form).toString() : undefined;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const headers: Record<string, string> = {};
      const cookieHeader = this.cookieHeader(url.hostname);
      if (cookieHeader) headers.cookie = cookieHeader;
      if (body !== undefined) headers['content-type'] = 'application/x-www-form-urlencoded';

      const response = await fetch(url, { method, headers, body, redirect: 'manual' });
      this.storeCookies(url.hostname, response.headers.getSetCookie());

      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location) {
        const next = new URL(location, url);
        if (options.stopWhen?.(next)) {
          return { status: response.status, url: next.href, body: '', headers: response.headers };
        }
        url = next;
        method = 'GET';
        body = undefined;
        continue;
      }
      return { status: response.status, url: url.href, body: await response.text(), headers: response.headers };
    }
    throw new Error(`Too many redirects starting at ${startUrl}`);
  }

  /** Finds the login form on a provider page and submits it. */
  async submitLogin(page: Page, username: string, password: string, options: NavigateOptions = {}): Promise<Page> {
    const action = /<form method="post" action="([^"]+\/login)"/.exec(page.body)?.[1];
    if (!action) throw new Error(`No login form on ${page.url}`);
    return this.navigate(new URL(action, page.url).href, { ...options, method: 'POST', form: { username, password } });
  }

  cookie(hostname: string, name: string): string | undefined {
    return this.jar.get(hostname)?.get(name);
  }

  private cookieHeader(hostname: string): string {
    return [...(this.jar.get(hostname) ?? new Map<string, string>())].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  private storeCookies(hostname: string, setCookies: string[]) {
    const cookies = this.jar.get(hostname) ?? new Map<string, string>();
    this.jar.set(hostname, cookies);
    for (const header of setCookies) {
      const [pair = '', ...attributes] = header.split(';');
      const index = pair.indexOf('=');
      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      const expired = attributes.some((a) => /^\s*max-age=0\s*$/i.test(a) || /^\s*expires=Thu, 01 Jan 1970/i.test(a));
      if (expired) {
        cookies.delete(name);
      } else if (name.length + value.length > BROWSER_COOKIE_LIMIT) {
        this.droppedCookies.push(name); // what Chrome, Firefox and Safari do
      } else {
        cookies.set(name, value);
      }
    }
  }
}
