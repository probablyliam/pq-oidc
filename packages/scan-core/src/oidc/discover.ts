/**
 * Looks for OpenID Connect (or OAuth authorization server) metadata, and if it
 * is there, reads the keys the service signs tokens with. This is the only way
 * an outside scan can learn anything about token signing; when nothing is
 * published, the answer is "could not determine", not a guess.
 *
 * Every URL in the metadata is attacker-controlled input. `jwks_uri` is put
 * through the same policy, resolution and pinning as a user-supplied target.
 */
import { analyzeProvider } from '@pq-oidc/token-kit/readiness';
import { FetchError, fetchPinned } from '../http/fetch.ts';
import type { FetchOptions } from '../http/fetch.ts';
import { parseTarget, TargetRejected } from '../net/policy.ts';
import type { TargetPolicy } from '../net/policy.ts';
import { resolveTarget } from '../net/resolve.ts';
import type { Lookup, PinnedTarget } from '../net/resolve.ts';
import type { OidcSummary, RelatedOrigin } from '../report.ts';

type Json = Record<string, unknown>;

const MAX_CANDIDATES = 5;

/**
 * Where metadata might live for a URL. An issuer may have a path
 * (https://idp.example/realms/a), so each path prefix is tried, deepest
 * first, then the OAuth well-known name at the root.
 */
export function discoveryCandidates(url: URL, includeFullPath: boolean): string[] {
  const segments = url.pathname.split('/').filter(Boolean);
  if (segments.at(-1) === 'openid-configuration' && segments.at(-2) === '.well-known') return [`${url.origin}${url.pathname}`];
  if (!includeFullPath) segments.pop(); // the last segment is an endpoint such as /authorize, not part of an issuer
  const candidates: string[] = [];
  for (let depth = segments.length; depth >= 0 && candidates.length < MAX_CANDIDATES - 1; depth--) {
    const prefix = segments.slice(0, depth).join('/');
    candidates.push(`${url.origin}${prefix ? `/${prefix}` : ''}/.well-known/openid-configuration`);
  }
  if (!candidates.includes(`${url.origin}/.well-known/openid-configuration`)) candidates.push(`${url.origin}/.well-known/openid-configuration`);
  candidates.push(`${url.origin}/.well-known/oauth-authorization-server`);
  return candidates;
}

export interface DiscoverOptions extends FetchOptions {
  lookup?: Lookup;
  /** True when `url` is what the user asked to scan (its whole path may be an issuer); false for an endpoint found in a redirect. */
  includeFullPath: boolean;
}

function parseJson(body: Buffer): Json | undefined {
  try {
    const value: unknown = JSON.parse(body.toString('utf8'));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Json) : undefined;
  } catch {
    return undefined;
  }
}

const originOf = (value: unknown): string | undefined => {
  try {
    return typeof value === 'string' ? new URL(value).origin : undefined;
  } catch {
    return undefined;
  }
};

export async function discoverOidc(url: URL, pinned: PinnedTarget, policy: TargetPolicy, options: DiscoverOptions): Promise<{ summary: OidcSummary; related: RelatedOrigin[] }> {
  const summary: OidcSummary = { found: false, tried: [] };
  const related: RelatedOrigin[] = [];
  let metadata: Json | undefined;

  for (const candidate of discoveryCandidates(url, options.includeFullPath)) {
    try {
      const response = await fetchPinned(new URL(candidate), pinned, { ...options, maxBytes: 256 * 1024 });
      const json = response.status === 200 ? parseJson(response.body) : undefined;
      if (json && typeof json.issuer === 'string') {
        summary.tried.push({ url: candidate, result: 'HTTP 200, metadata found' });
        summary.discoveryUrl = candidate;
        metadata = json;
        break;
      }
      summary.tried.push({ url: candidate, result: response.status === 200 ? 'HTTP 200, but not a metadata document' : `HTTP ${response.status}` });
    } catch (error) {
      if (!(error instanceof FetchError)) throw error;
      summary.tried.push({ url: candidate, result: error.message });
    }
  }
  if (!metadata || !summary.discoveryUrl) return { summary, related };

  summary.found = true;
  summary.issuer = String(metadata.issuer);
  const servedFrom = summary.discoveryUrl.replace(/\/\.well-known\/(openid-configuration|oauth-authorization-server)$/, '');
  summary.issuerMatches = summary.issuer.replace(/\/$/, '') === servedFrom;
  summary.idTokenAlgs = Array.isArray(metadata.id_token_signing_alg_values_supported) ? metadata.id_token_signing_alg_values_supported.map(String) : [];

  for (const [field, role] of [
    ['authorization_endpoint', 'authorization endpoint named in the metadata'],
    ['token_endpoint', 'token endpoint named in the metadata'],
    ['jwks_uri', 'publishes the token signing keys'],
  ] as const) {
    const origin = originOf(metadata[field]);
    if (origin && origin !== url.origin && !related.some((r) => r.origin === origin)) related.push({ origin, role });
  }

  if (typeof metadata.jwks_uri !== 'string') {
    summary.jwksError = 'The metadata has no jwks_uri.';
    return { summary, related };
  }
  summary.jwksUri = metadata.jwks_uri;
  try {
    const jwksTarget = parseTarget(metadata.jwks_uri, policy);
    const jwksPinned = jwksTarget.origin === url.origin ? pinned : await resolveTarget(jwksTarget, { lookup: options.lookup });
    const response = await fetchPinned(jwksTarget.url, jwksPinned, { ...options, maxBytes: 512 * 1024 });
    const jwks = response.status === 200 && !response.truncated ? parseJson(response.body) : undefined;
    if (!jwks || !Array.isArray(jwks.keys)) {
      summary.jwksError = response.truncated ? 'The key set is larger than 512 kB.' : `The key set could not be read (HTTP ${response.status}).`;
    } else {
      summary.keys = analyzeProvider(metadata, jwks, response.body.length).keys.filter((k) => k.use !== 'enc');
    }
  } catch (error) {
    if (error instanceof TargetRejected) summary.jwksError = `The scanner will not fetch jwks_uri: ${error.message}`;
    else if (error instanceof FetchError) summary.jwksError = error.message;
    else throw error;
  }
  return { summary, related };
}
