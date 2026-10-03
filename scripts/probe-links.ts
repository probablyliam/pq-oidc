/** What the sign-in link finder sees on a real page: size, truncation, every candidate anchor, and what it picks. */
import { fetchFollowingRedirects } from '../packages/scan-core/src/http/fetch.ts';
import { findSignInLinks } from '../packages/scan-core/src/http/page.ts';
import { DEFAULT_POLICY, parseTarget } from '../packages/scan-core/src/net/policy.ts';
import { resolveTarget } from '../packages/scan-core/src/net/resolve.ts';

const target = parseTarget(process.argv[2]!, DEFAULT_POLICY);
const pinned = await resolveTarget(target, {});
const follow = await fetchFollowingRedirects(target, pinned, DEFAULT_POLICY, { maxBytes: 256 * 1024 });
const last = follow.responses.at(-1)!;
const html = last.response.body.toString('utf8');
console.log('final', last.response.status, last.response.url, `${html.length} chars`, last.response.truncated ? 'TRUNCATED' : 'complete');
console.log('anchors in total:', (html.match(/<a\b/gi) ?? []).length, '| first <a at char', html.search(/<a\b/i), '| "Sign in" text at char', html.search(/sign\s?in/i));
for (const m of html.matchAll(/<a\b[^>]*>[\s\S]{0,200}?<\/a>/gi)) if (/sign\s?-?in|log\s?-?in|login/i.test(m[0])) console.log('  ', m[0].replace(/\s+/g, ' ').slice(0, 200));
console.log('picked:', findSignInLinks(html, new URL(last.response.url)));
// Context around the first "Sign in" text and the first /login href, to see what markup the finder is missing.
for (const re of [/sign\s?in/i, /href="\/login/i, /href=".*?login[^"]*"/i]) {
  const at = html.search(re);
  if (at >= 0) console.log(`\n--- ${re} at ${at}:\n` + html.slice(Math.max(0, at - 420), at + 140).replace(/\s+/g, ' '));
}
