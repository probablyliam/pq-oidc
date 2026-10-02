/**
 * What kind of address was scanned, as far as one fetch of it shows: a
 * sign-in service, a page with a sign-in form, an address that sends
 * visitors on to sign in somewhere else, or none of these.
 *
 * Only the HTML the server sent is read. A page that builds its form with
 * JavaScript after loading has no password field in that HTML, so "none of
 * these" means none was found, not that the site has no login.
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

export function summarizePage(follow: FollowResult, targetOrigin: string, oidc: OidcSummary): PageSummary {
  const last = follow.responses.at(-1);
  const leadsTo = last && last.target.origin !== targetOrigin ? last.target.origin : undefined;
  const contentType = String(last?.response.headers['content-type'] ?? '');
  const html = last && /html/i.test(contentType) ? last.response.body.toString('utf8') : '';
  const field = findPasswordField(html);
  const metadataAt = oidc.found && oidc.discoveryUrl ? new URL(oidc.discoveryUrl).origin : undefined;

  const evidence: PageSummary['evidence'] = [];
  if (last) evidence.push({ label: 'Page read', value: `${last.response.url} (${last.response.status}, ${html ? `${last.response.body.length.toLocaleString('en-US')} bytes of HTML${last.response.truncated ? ', cut short' : ''}` : contentType || 'no content type'})` });
  if (field) evidence.push({ label: 'Password field', value: field });
  if (metadataAt) evidence.push({ label: 'OpenID Connect metadata', value: oidc.discoveryUrl! });

  if (metadataAt === targetOrigin) return { kind: 'sign-in-service', evidence };
  if (field && !leadsTo) return { kind: 'sign-in-page', evidence };
  if (leadsTo && (field || metadataAt === leadsTo)) return { kind: 'leads-to-sign-in', leadsTo, evidence };
  return { kind: 'other', leadsTo, evidence };
}
