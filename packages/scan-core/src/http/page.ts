/**
 * What kind of address was scanned, as far as one fetch of it shows: a
 * sign-in service, a page with a sign-in form, an address that sends
 * visitors on to sign in somewhere else, or none of these.
 *
 * Only the HTML the server sent is read, so a form that a script builds after
 * loading is not seen. Modern sign-in pages are mostly like that (they ask for
 * a username first, then build the rest), which is why the address itself
 * also counts: an OAuth "authorize" endpoint or a "/login" path is a sign-in
 * by convention. The report says which of these it went on (`how`), with the
 * strongest first: published metadata, a password field, a username field,
 * the address. "Other" means none was found, not that the site has no login.
 */
import type { OidcSummary, PageSummary } from '../report.ts';
import type { FollowResult } from './fetch.ts';

/** The first password input in an HTML document, as written there, or undefined. */
export function findPasswordField(html: string): string | undefined {
  for (const [tag] of html.matchAll(/<input\b[^>]*>/gi)) {
    const password = /\btype\s*=\s*["']?password["'\s/>]/i.test(tag) || /\bautocomplete\s*=\s*["'][^"']*\b(?:current|new)-password\b/i.test(tag);
    if (password) return tag.slice(0, 160);
  }
  return undefined;
}

/** The first visible username, login or email input: the first step of a two-step sign-in. */
export function findUsernameField(html: string): string | undefined {
  for (const [tag] of html.matchAll(/<input\b[^>]*>/gi)) {
    if (/\btype\s*=\s*["']?hidden\b/i.test(tag)) continue;
    const username =
      /\bautocomplete\s*=\s*["'][^"']*\busername\b/i.test(tag) || /\btype\s*=\s*["']?email\b/i.test(tag) || /\bname\s*=\s*["']?(?:username|user|login|loginfmt|identifier|email)\b/i.test(tag);
    if (username) return tag.slice(0, 160);
  }
  return undefined;
}

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#x27': "'" };

/** The usual places a sign-in lives, tried in this order when a page does not link to one. */
export const SIGN_IN_PATHS = ['/login', '/signin', '/sign-in', '/account/login', '/auth/login', '/users/sign_in'];

/**
 * Links on a page that lead to a sign-in, best first: one that says "sign in"
 * or "log in" outranks one whose address merely looks like it. Only https
 * links are returned, resolved against the page's address; whoever follows
 * them puts each through the policy first.
 */
export function findSignInLinks(html: string, base: URL, limit = 3): string[] {
  const scored = new Map<string, number>();
  // A link's text can sit inside nested spans with long class names (GitHub's "Sign in" runs to ~500 characters), so the window is generous.
  for (const [, attrs = '', inner = ''] of html.matchAll(/<a\b([^>]*)>([\s\S]{0,2000}?)<\/a>/gi)) {
    const href = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
    // An href in HTML carries entities: the & between query parameters is written &amp;.
    const raw = (href?.[1] ?? href?.[2] ?? href?.[3] ?? '').trim().replace(/&(amp|lt|gt|quot|#39|#x27);/g, (_, e: string) => ENTITIES[e] ?? _);
    if (!raw || /^(?:javascript|mailto|tel):|^#/i.test(raw)) continue;
    let url: URL;
    try {
      url = new URL(raw, base);
    } catch {
      continue;
    }
    if (url.protocol !== 'https:') continue;
    url.hash = '';
    const text = inner.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    const label = `${text} ${/\baria-label\s*=\s*"([^"]*)"/i.exec(attrs)?.[1] ?? ''} ${/\btitle\s*=\s*"([^"]*)"/i.exec(attrs)?.[1] ?? ''}`;
    const byText = /\b(?:sign|log)\s?-?in\b/i.test(label) ? 2 : /\b(?:my )?account\b/i.test(label) ? 1 : 0;
    const byPath = /(?:^|\/)(?:sign-?in|log-?in|login|auth|account)(?:\/|$)/i.test(url.pathname) ? 1 : 0;
    if (byText + byPath === 0) continue;
    const score = byText * 2 + byPath;
    scored.set(url.href, Math.max(scored.get(url.href) ?? 0, score));
  }
  return [...scored.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([href]) => href);
}

/** A path that is a sign-in endpoint by convention: OAuth's authorize endpoint, or the usual names. */
export function signInPath(url: URL): string | undefined {
  return /(?:^|\/)(?:authorize|signin|sign-in|login|log-in|sso|saml2?)(?:\/|$)/i.test(url.pathname) ? url.pathname : undefined;
}

export function summarizePage(follow: FollowResult, targetOrigin: string, oidc: OidcSummary): PageSummary {
  const last = follow.responses.at(-1);
  const leadsTo = last && last.target.origin !== targetOrigin ? last.target.origin : undefined;
  const contentType = String(last?.response.headers['content-type'] ?? '');
  const html = last && /html/i.test(contentType) ? last.response.body.toString('utf8') : '';
  const password = findPasswordField(html);
  const username = password ? undefined : findUsernameField(html);
  const path = last ? signInPath(new URL(last.response.url)) : undefined;
  const metadataAt = oidc.found && oidc.discoveryUrl ? new URL(oidc.discoveryUrl).origin : undefined;

  const evidence: PageSummary['evidence'] = [];
  if (last) {
    const size = html ? `${last.response.body.length.toLocaleString('en-US')} bytes of HTML${last.response.truncated ? ', cut short' : ''}` : contentType || 'no content type';
    evidence.push({ label: 'Page read', value: `${last.response.url} (${last.response.status}, ${size})` });
  }
  if (metadataAt) evidence.push({ label: 'OpenID Connect metadata', value: oidc.discoveryUrl! });
  if (password) evidence.push({ label: 'Password field', value: password });
  if (username) evidence.push({ label: 'Username field', value: username });
  if (path) evidence.push({ label: 'Sign-in address', value: path });

  const how: PageSummary['how'] = password ? 'password-field' : username ? 'username-field' : path ? 'address' : undefined;
  if (metadataAt === targetOrigin) return { kind: 'sign-in-service', how: 'metadata', evidence };
  if (how && !leadsTo) return { kind: 'sign-in-page', how, evidence };
  if (leadsTo && (how || metadataAt === leadsTo)) return { kind: 'leads-to-sign-in', how: metadataAt === leadsTo ? 'metadata' : how, leadsTo, evidence };
  return { kind: 'other', leadsTo, evidence };
}
