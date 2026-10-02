/**
 * One scan, start to finish:
 *
 *   parse and check the target  →  resolve once, pin an address
 *   →  TLS handshakes (probes.ts)  →  certificate summary
 *   →  HTTPS GET with hand-followed redirects, plain-HTTP check
 *   →  OpenID Connect metadata and keys
 *   →  findings (assess.ts)
 *
 * The whole thing works against a deadline. A step that would start too late
 * is skipped and the report says so, rather than the scan hanging.
 */
import { assess } from './assess.ts';
import { fetchFollowingRedirects } from './http/fetch.ts';
import type { FollowResult } from './http/fetch.ts';
import { summarizePage } from './http/page.ts';
import { checkPlainHttp, summarizeTransport } from './http/transport.ts';
import { DEFAULT_POLICY, parseTarget } from './net/policy.ts';
import type { TargetPolicy } from './net/policy.ts';
import { resolveTarget } from './net/resolve.ts';
import type { Lookup } from './net/resolve.ts';
import { discoverOidc } from './oidc/discover.ts';
import { ENGINE_VERSION } from './report.ts';
import type { OidcSummary, RelatedOrigin, ScanReport, TrustResult } from './report.ts';
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

/**
 * Scans one target. Throws TargetRejected if the target is refused before or
 * during resolution; everything after that is reported inside the report.
 */
export async function runScan(input: string, options: ScanOptions = {}): Promise<ScanReport> {
  const policy = options.policy ?? DEFAULT_POLICY;
  const progress = options.onProgress ?? (() => {});
  const started = new Date();
  const deadline = started.getTime() + (options.budgetMs ?? 60_000);

  const target = parseTarget(input, policy);
  progress(`Resolving ${target.hostname}`);
  const pinned = await resolveTarget(target, { lookup: options.lookup });

  const tls = await probeTls(pinned, { onProgress: progress, deadline });
  const certificates = summarizeChain(tls.certificates);

  let follow: FollowResult = { hops: [], responses: [] };
  let plainHttp;
  let oidc: OidcSummary = { found: false, tried: [] };
  const related: RelatedOrigin[] = [];
  const relate = (origin: string, role: string) => {
    if (origin !== target.origin && !related.some((r) => r.origin === origin)) related.push({ origin, role });
  };

  if (tls.reachable) {
    progress('Fetching the page over HTTPS');
    follow = await fetchFollowingRedirects(target, pinned, policy, { lookup: options.lookup, deadline });
    for (const { target: hop } of follow.responses) relate(hop.origin, 'the page redirects here');

    // Port 80 only makes sense as the plain-HTTP twin of the default HTTPS port, and a lab server has none.
    if (target.port === 443 && !target.isLab && Date.now() < deadline) {
      progress('Checking what plain HTTP does');
      plainHttp = await checkPlainHttp(pinned, Math.min(4000, deadline - Date.now()));
    }

    progress('Looking for OpenID Connect metadata');
    const own = await discoverOidc(target.url, pinned, policy, { lookup: options.lookup, deadline, includeFullPath: true });
    oidc = own.summary;
    own.related.forEach((r) => relate(r.origin, r.role));

    // A login page that hands off to an identity provider: the tokens are signed there, so look there too.
    const last = follow.responses.at(-1);
    if (!oidc.found && last && last.target.origin !== target.origin) {
      progress(`Looking for OpenID Connect metadata at ${last.target.hostname}`);
      const idp = await discoverOidc(last.target.url, last.pinned, policy, { lookup: options.lookup, deadline, includeFullPath: false });
      if (idp.summary.found) {
        oidc = { ...idp.summary, tried: [...oidc.tried, ...idp.summary.tried] };
        related.splice(0, related.length, ...related.map((r) => (r.origin === last.target.origin ? { ...r, role: 'identity provider: the page redirects here to sign in, and its keys sign the tokens' } : r)));
        idp.related.forEach((r) => relate(r.origin, r.role));
      } else {
        oidc = { ...oidc, tried: [...oidc.tried, ...idp.summary.tried] };
      }
    }
  }

  const first = follow.responses[0]?.response.tls;
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
    page: summarizePage(follow, target.origin, oidc),
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
