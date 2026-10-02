/**
 * What one fetch of an address actually shows, for tuning the sign-in
 * detection: the redirect chain, what the final HTML contains, and where
 * OpenID Connect metadata was looked for. Run: node scripts/probe-page.ts <url>
 */
import { fetchFollowingRedirects } from '../packages/scan-core/src/http/fetch.ts';
import { DEFAULT_POLICY, parseTarget } from '../packages/scan-core/src/net/policy.ts';
import { resolveTarget } from '../packages/scan-core/src/net/resolve.ts';
import { discoverOidc } from '../packages/scan-core/src/oidc/discover.ts';

const input = process.argv[2];
if (!input) throw new Error('usage: probe-page <url>');
const target = parseTarget(input, DEFAULT_POLICY);
const pinned = await resolveTarget(target, {});
const follow = await fetchFollowingRedirects(target, pinned, DEFAULT_POLICY, {});
for (const hop of follow.hops) console.log('hop', hop.status, hop.url, hop.location ?? '', hop.error ?? '');
const last = follow.responses.at(-1);
if (last) {
  const html = last.response.body.toString('utf8');
  const inputs = [...html.matchAll(/<input\b[^>]*>/gi)].map((m) => m[0].slice(0, 140));
  console.log('final', last.response.status, last.response.url, String(last.response.headers['content-type']), `${last.response.body.length} bytes`, last.response.truncated ? 'TRUNCATED' : '');
  console.log('inputs:', inputs.length);
  for (const tag of inputs.slice(0, 12)) console.log('  ', tag);
  console.log('forms:', [...html.matchAll(/<form\b[^>]*>/gi)].map((m) => m[0].slice(0, 160)));
  console.log('title:', /<title[^>]*>([^<]*)/i.exec(html)?.[1]?.trim());
}
const oidc = await discoverOidc(target.url, pinned, DEFAULT_POLICY, { includeFullPath: true });
console.log('oidc found:', oidc.summary.found, oidc.summary.discoveryUrl ?? '');
for (const t of oidc.summary.tried) console.log('  tried', t.url, '->', t.result);
