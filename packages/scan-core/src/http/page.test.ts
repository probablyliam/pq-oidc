import { describe, expect, it } from 'vitest';
import { parseTarget, DEFAULT_POLICY } from '../net/policy.ts';
import type { PinnedTarget } from '../net/resolve.ts';
import type { OidcSummary } from '../report.ts';
import { plainSummary } from '../summary.ts';
import type { FollowResult, HttpResponse } from './fetch.ts';
import { findPasswordField, summarizePage } from './page.ts';

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

describe('what kind of address was scanned', () => {
  it('a page with a password field is a sign-in page', () => {
    const page = summarizePage(chain({ url: 'https://example.com/login', html: '<form><input type="password"></form>' }), 'https://example.com', noOidc);
    expect(page).toMatchObject({ kind: 'sign-in-page' });
    expect(page.evidence.find((e) => e.label === 'Password field')?.value).toBe('<input type="password">');
  });

  it('an origin that publishes OpenID Connect metadata is a sign-in service, whatever its page shows', () => {
    const oidc = { found: true, tried: [], discoveryUrl: 'https://idp.example.com/.well-known/openid-configuration' } as OidcSummary;
    expect(summarizePage(chain({ url: 'https://idp.example.com/', html: '<h1>Hi</h1>' }), 'https://idp.example.com', oidc).kind).toBe('sign-in-service');
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
  });

  it('the plain summary names the kind, and does not ask about a sign-in that is not there', () => {
    const report = {
      reachable: true,
      layers: [{ id: 'key-establishment', exposure: 'no-known-attack', headline: 'Hybrid: X25519MLKEM768' }],
      findings: [],
      page: { kind: 'other', evidence: [] },
    } as unknown as Parameters<typeof plainSummary>[0];
    const summary = plainSummary(report);
    expect(summary.page).toEqual({ kind: 'other', note: 'No sign-in found on this page.', leadsTo: undefined });
    expect(summary.answers.find((a) => a.id === 'sign-in')).toMatchObject({ status: 'unknown', short: 'No sign-in found' });
  });
});
