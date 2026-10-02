import { describe, expect, it } from 'vitest';
import { parseTarget, DEFAULT_POLICY } from '../net/policy.ts';
import type { PinnedTarget } from '../net/resolve.ts';
import type { OidcSummary } from '../report.ts';
import { plainSummary } from '../summary.ts';
import type { FollowResult, HttpResponse } from './fetch.ts';
import { findPasswordField, findUsernameField, signInPath, summarizePage } from './page.ts';

const pinned = {} as PinnedTarget;
const noOidc: OidcSummary = { found: false, tried: [] };

function chain(...pages: { url: string; html?: string; type?: string; status?: number }[]): FollowResult {
  return {
    hops: pages.map((p) => ({ url: p.url, status: p.status ?? 200 })),
    responses: pages.map((p) => ({
      target: parseTarget(p.url, DEFAULT_POLICY),
      pinned,
      response: { url: p.url, status: p.status ?? 200, headers: { 'content-type': p.type ?? 'text/html; charset=utf-8' }, body: Buffer.from(p.html ?? ''), truncated: false } as HttpResponse,
    })),
  };
}

describe('finding a password field in the HTML a server sent', () => {
  it.each([
    ['<input type="password" name="pw">'],
    ["<INPUT name=pw TYPE='Password'>"],
    ['<input name=pw type=password>'],
    ['<input id="p" autocomplete="current-password">'],
    ['<input autocomplete="username new-password" type="text">'],
  ])('finds %s', (tag) => {
    expect(findPasswordField(`<form>${tag}<button>Go</button></form>`)).toBe(tag);
  });

  it.each([
    ['<input type="text" name="password">'],
    ['<input type="passwords">'],
    ['<p>Forgot your password?</p>'],
    ['<script>const html = "type=password"</script>'],
  ])('ignores %s', (html) => {
    expect(findPasswordField(html)).toBeUndefined();
  });
});

describe('the first step of a two-step sign-in, and sign-in addresses', () => {
  it.each([
    ['<input type="text" name="login" autocomplete="username">'],
    ['<input type="email" name="loginfmt">'],
    ['<input name="identifier">'],
  ])('a visible username field counts: %s', (tag) => {
    expect(findUsernameField(`<form>${tag}</form>`)).toBe(tag);
  });

  it('a hidden field does not, whatever it is called', () => {
    expect(findUsernameField('<input type="hidden" name="login" value="x"><input type="hidden" name="return_to">')).toBeUndefined();
  });

  it.each([
    ['https://login.example.com/common/oauth2/v2.0/authorize?client_id=x', '/common/oauth2/v2.0/authorize'],
    ['https://accounts.example.com/v3/signin/identifier', '/v3/signin/identifier'],
    ['https://example.com/login', '/login'],
    ['https://example.com/sso/start', '/sso/start'],
  ])('%s is a sign-in address', (url, path) => {
    expect(signInPath(new URL(url))).toBe(path);
  });

  it.each(['https://example.com/', 'https://example.com/blog/logins-are-hard', 'https://example.com/watch?v=signin'])('%s is not', (url) => {
    expect(signInPath(new URL(url))).toBeUndefined();
  });
});

describe('what kind of address was scanned', () => {
  it('a page with a password field is a sign-in page', () => {
    const page = summarizePage(chain({ url: 'https://example.com/login', html: '<form><input type="password"></form>' }), 'https://example.com', noOidc);
    expect(page).toMatchObject({ kind: 'sign-in-page', how: 'password-field' });
    expect(page.evidence.find((e) => e.label === 'Password field')?.value).toBe('<input type="password">');
  });

  it('an origin that publishes OpenID Connect metadata is a sign-in service, whatever its page shows', () => {
    const oidc = { found: true, tried: [], discoveryUrl: 'https://idp.example.com/.well-known/openid-configuration' } as OidcSummary;
    expect(summarizePage(chain({ url: 'https://idp.example.com/', html: '<h1>Hi</h1>' }), 'https://idp.example.com', oidc).kind).toBe('sign-in-service');
  });

  it('a sign-in that asks for a username first, or that lives at a sign-in address with a script-built form, still counts, and says so', () => {
    const first = summarizePage(chain({ url: 'https://example.com/', html: '<form><input type="email" name="loginfmt"></form>' }), 'https://example.com', noOidc);
    expect(first).toMatchObject({ kind: 'sign-in-page', how: 'username-field' });
    // The shape of a Microsoft sign-in: out to another origin and back to an OAuth authorize endpoint, with no form in the HTML.
    const bounced = summarizePage(
      chain({ url: 'https://login.example.com/', status: 302 }, { url: 'https://www.example.com/login', status: 302 }, { url: 'https://login.example.com/common/oauth2/v2.0/authorize?client_id=x', html: '<div id="app"></div>' }),
      'https://login.example.com',
      noOidc,
    );
    expect(bounced).toMatchObject({ kind: 'sign-in-page', how: 'address' });
    expect(bounced.evidence.find((e) => e.label === 'Sign-in address')?.value).toBe('/common/oauth2/v2.0/authorize');
  });

  it('an address that redirects to a sign-in somewhere else says where', () => {
    const page = summarizePage(
      chain({ url: 'https://app.example.com/', status: 302 }, { url: 'https://login.example.net/authorize', html: '<input type=password>' }),
      'https://app.example.com',
      noOidc,
    );
    expect(page).toMatchObject({ kind: 'leads-to-sign-in', leadsTo: 'https://login.example.net' });
  });

  it('a page without any of that is reported as no sign-in found, and a script-built form is not guessed at', () => {
    const page = summarizePage(chain({ url: 'https://video.example.com/', html: '<div id="app"></div><script src="app.js"></script>' }), 'https://video.example.com', noOidc);
    expect(page).toMatchObject({ kind: 'other' });
    expect(summarizePage(chain({ url: 'https://example.com/data.json', html: '{"type":"password"}', type: 'application/json' }), 'https://example.com', noOidc).kind).toBe('other');
    const watch = summarizePage(chain({ url: 'https://example.com/watch?v=abc', html: '<input type="search" name="q">' }), 'https://example.com', noOidc);
    expect(watch.kind).toBe('other');
    expect(watch.how).toBeUndefined();
  });

  it('the plain summary names the kind, and does not ask about a sign-in that is not there', () => {
    const report = {
      reachable: true,
      layers: [{ id: 'key-establishment', exposure: 'no-known-attack', headline: 'Hybrid: X25519MLKEM768' }],
      findings: [],
      page: { kind: 'other', evidence: [] },
    } as unknown as Parameters<typeof plainSummary>[0];
    const summary = plainSummary(report);
    expect(summary.page).toEqual({ kind: 'other', note: 'Not a sign-in page. A scan can still check the connection and the site’s identity below.', leadsTo: undefined });
    expect(summary.answers.find((a) => a.id === 'sign-in')).toMatchObject({ status: 'unknown', short: 'No sign-in found' });
  });
});
