/**
 * One scan, start to finish:
 *
 *   parse and check the address  →  resolve once, pin an address
 *   →  HTTPS GET with hand-followed redirects; if that page is not a
 *      sign-in, look for one: the site's own "Sign in" link, then the usual
 *      paths. The sign-in's origin is what the rest of the scan is about,
 *      since that is where a password would go.
 *   →  TLS handshakes (probes.ts)  →  certificate summary  →  plain-HTTP check
 *   →  OpenID Connect metadata and keys
 *   →  findings (assess.ts)
 *
 * Every address the scanner goes on to, found or redirected to, is put
 * through the same policy, resolution and pinning as the one it was given.
 * The whole thing works against a deadline. A step that would start too late
 * is skipped and the report says so, rather than the scan hanging.
 */
import { assess } from './assess.ts';
import { fetchFollowingRedirects } from './http/fetch.ts';
import type { FollowResult } from './http/fetch.ts';
import { findSignInLinks, SIGN_IN_PATHS, summarizePage } from './http/page.ts';
import { checkPlainHttp, summarizeTransport } from './http/transport.ts';
import { DEFAULT_POLICY, parseTarget, TargetRejected } from './net/policy.ts';
import type { Target, TargetPolicy } from './net/policy.ts';
import { resolveTarget } from './net/resolve.ts';
import type { Lookup, PinnedTarget } from './net/resolve.ts';
import { discoverOidc } from './oidc/discover.ts';
import { ENGINE_VERSION } from './report.ts';
import type { OidcSummary, PageSummary, RelatedOrigin, ScanReport, TrustResult } from './report.ts';
import { probeTls } from './tls/probes.ts';
import { summarizeChain } from './x509/summary.ts';

export interface ScanOptions {
  policy?: TargetPolicy;
  /** DNS, injectable for tests. */
  lookup?: Lookup;
  /** Called as each step starts, with a short description for the person waiting. */
  onProgress?: (step: string) => void;
  /** Longest the whole scan may take. */
  budgetMs?: number;
}

const TRUST_STORE = `the CA certificates shipped with Node.js ${process.version} (Mozilla’s list)`;
/** How many places the scanner will fetch looking for a sign-in it was not given. */
const MAX_SIGN_IN_FETCHES = 3;
const NO_OIDC: OidcSummary = { found: false, tried: [] };

/** A page the scanner fetched, with what kind of page it turned out to be. */
interface Landing {
  target: Target;
  follow: FollowResult;
  page: PageSummary;
}

/** Fetches an address through the policy and classifies the page. Pins are shared, so an origin is resolved once. */
async function land(target: Target, pins: Map<string, PinnedTarget>, policy: TargetPolicy, lookup: Lookup | undefined, deadline: number): Promise<Landing> {
  let pinned = pins.get(target.origin);
  if (!pinned) pins.set(target.origin, (pinned = await resolveTarget(target, { lookup })));
  // A home page's head alone can pass 64 kB; the "Sign in" link is in the body after it.
  const follow = await fetchFollowingRedirects(target, pinned, policy, { lookup, deadline, maxBytes: 256 * 1024 });
  for (const hop of follow.responses) pins.set(hop.target.origin, hop.pinned);
  return { target, follow, page: summarizePage(follow, target.origin, NO_OIDC) };
}

/**
 * Scans one address. Throws TargetRejected if the address is refused before or
 * during resolution; everything after that is reported inside the report.
 */
export async function runScan(input: string, options: ScanOptions = {}): Promise<ScanReport> {
  const policy = options.policy ?? DEFAULT_POLICY;
  const progress = options.onProgress ?? (() => {});
  const started = new Date();
  const deadline = started.getTime() + (options.budgetMs ?? 60_000);

  const entered = parseTarget(input, policy);
  progress(`Resolving ${entered.hostname}`);
  const pins = new Map<string, PinnedTarget>([[entered.origin, await resolveTarget(entered, { lookup: options.lookup })]]);

  // ---- The page, and if it is not a sign-in, the search for one.
  progress('Fetching the page over HTTPS');
  let landing = await land(entered, pins, policy, options.lookup, deadline);
  let found: PageSummary['found'];
  const searched: PageSummary['evidence'] = [];
  const endOf = (l: Landing) => l.follow.responses.at(-1);

  // Only a real page that is not a sign-in starts a search. A missing page, an error, or a redirect
  // the policy refused is reported as what the typed address does, with nothing substituted for it.
  const typedPage = endOf(landing);
  const html = typedPage && typedPage.response.status === 200 && /html/i.test(String(typedPage.response.headers['content-type'] ?? '')) ? typedPage.response.body.toString('utf8') : '';
  if (landing.page.kind === 'leads-to-sign-in') {
    found = { by: 'redirect', url: typedPage!.response.url };
  } else if (landing.page.kind === 'other' && html && !landing.follow.blockedRedirect && Date.now() < deadline) {
    const base = new URL(typedPage!.response.url);
    const candidates = [
      ...findSignInLinks(html, base, 2).map((url) => ({ url, by: 'link' as const })),
      ...SIGN_IN_PATHS.map((path) => ({ url: new URL(path, base.origin).href, by: 'convention' as const })),
    ];
    const seen = new Set([entered.url.href, ...landing.follow.responses.map((r) => r.response.url)]);
    const refused = (url: string, error: unknown) => {
      if (!(error instanceof TargetRejected)) throw error;
      searched.push({ label: 'Looked for a sign-in', value: `${url}: refused (${error.code})` });
    };
    let fetches = 0;
    for (const candidate of candidates) {
      if (fetches >= MAX_SIGN_IN_FETCHES || Date.now() >= deadline) break;
      if (seen.has(candidate.url)) continue;
      seen.add(candidate.url);
      let target: Target;
      try {
        target = parseTarget(candidate.url, policy);
      } catch (error) {
        refused(candidate.url, error);
        continue;
      }
      progress(`Looking for the sign-in at ${target.hostname}${target.url.pathname}`);
      fetches++;
      let attempt: Landing;
      try {
        attempt = await land(target, pins, policy, options.lookup, deadline);
      } catch (error) {
        refused(candidate.url, error);
        continue;
      }
      const end = endOf(attempt);
      if (end && (attempt.page.kind === 'sign-in-page' || attempt.page.kind === 'leads-to-sign-in')) {
        found = { by: candidate.by, url: end.response.url };
        landing = attempt;
        searched.push({ label: 'Looked for a sign-in', value: `${candidate.url}: found, ${candidate.by === 'link' ? 'by the site’s own link' : 'at a usual address'}` });
        break;
      }
      searched.push({ label: 'Looked for a sign-in', value: `${candidate.url}: ${end ? `HTTP ${end.response.status}, ` : ''}not a sign-in` });
    }
  }

  // ---- From here on the scan is about where the sign-in is: the last page the chain reached.
  const end = endOf(landing);
  const target = end?.target ?? landing.target;
  const pinned = pins.get(target.origin)!;
  const follow = landing.follow;
  const switched = target.origin !== entered.origin;

  const tls = await probeTls(pinned, { onProgress: progress, deadline });
  const certificates = summarizeChain(tls.certificates);

  const related: RelatedOrigin[] = [];
  const relate = (origin: string, role: string) => {
    if (origin !== target.origin && !related.some((r) => r.origin === origin)) related.push({ origin, role });
  };
  if (switched) relate(entered.origin, found ? 'the address you entered; its sign-in is here' : 'the address you entered; it sends visitors here');
  for (const hop of follow.responses) relate(hop.target.origin, 'the page redirects through here');

  let plainHttp;
  let oidc: OidcSummary = NO_OIDC;
  if (tls.reachable) {
    // Port 80 only makes sense as the plain-HTTP twin of the default HTTPS port, and a lab server has none.
    if (target.port === 443 && !target.isLab && Date.now() < deadline) {
      progress('Checking what plain HTTP does');
      plainHttp = await checkPlainHttp(pinned, Math.min(4000, deadline - Date.now()));
    }

    // Metadata may sit under the path the user typed (an issuer such as /realms/x); under a path the site
    // sent us to, it sits above the endpoint (login.microsoftonline.com keeps it under /common).
    progress('Looking for OpenID Connect metadata');
    const typed = target.url.href === entered.url.href;
    const discovery = await discoverOidc(target.url, pinned, policy, { lookup: options.lookup, deadline, includeFullPath: typed });
    oidc = discovery.summary;
    discovery.related.forEach((r) => relate(r.origin, r.role));
  }

  const page = summarizePage(follow, target.origin, oidc);
  if (found) page.found = found;
  page.evidence.push(...searched);

  const first = follow.responses.find((r) => r.target.origin === target.origin)?.response.tls;
  const trust: TrustResult = first
    ? { checked: true, trusted: first.authorized, error: first.authorized ? undefined : describeTrustError(first.authorizationError), store: TRUST_STORE }
    : { checked: false, store: TRUST_STORE };
  const transport = summarizeTransport(follow, target.origin, plainHttp);

  const { layers, findings } = assess({
    hostname: target.hostname,
    lab: target.isLab,
    reachable: tls.reachable,
    probes: tls.probes,
    groupSupport: tls.groupSupport,
    certificates,
    trust,
    transport,
    oidc,
    related,
  });

  const finished = new Date();
  return {
    schema: 1,
    engine: ENGINE_VERSION,
    target: { input, url: target.url.href, origin: target.origin, hostname: target.hostname, port: target.port, lab: target.isLab },
    entered: switched ? { url: entered.url.href, origin: entered.origin } : undefined,
    startedAt: started.toISOString(),
    finishedAt: finished.toISOString(),
    durationMs: finished.getTime() - started.getTime(),
    network: { address: pinned.address, family: pinned.family, resolved: pinned.resolved.map((r) => r.address) },
    reachable: tls.reachable,
    tls: { probes: tls.probes, groupSupport: tls.groupSupport },
    certificates,
    trust,
    transport,
    oidc,
    page,
    related,
    layers,
    findings,
  };
}

/** OpenSSL's verification codes, in words. */
function describeTrustError(code: string | undefined): string {
  const known: Record<string, string> = {
    DEPTH_ZERO_SELF_SIGNED_CERT: 'the certificate is self-signed',
    SELF_SIGNED_CERT_IN_CHAIN: 'the chain ends in a certificate authority that is not in the trust store',
    UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'the issuing certificate authority is not in the trust store',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'the chain is incomplete: the issuer of the certificate was not sent and is not in the trust store',
    CERT_HAS_EXPIRED: 'the certificate has expired',
    CERT_NOT_YET_VALID: 'the certificate is not valid yet',
    ERR_TLS_CERT_ALTNAME_INVALID: 'the certificate is for a different host name',
    CERT_REVOKED: 'the certificate was revoked',
  };
  return known[code ?? ''] ?? code ?? 'validation failed';
}
