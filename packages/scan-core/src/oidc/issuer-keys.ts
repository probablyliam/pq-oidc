/**
 * Fetches an issuer's OpenID Connect metadata and public keys, for a browser
 * that was not allowed to fetch them itself (the issuer sends no CORS
 * headers). Only the issuer URL reaches the service; the token being checked
 * stays in the browser (ADR 0010). The issuer URL comes from a token, so it
 * goes through the same policy, resolution and pinning as any scan target.
 */
import { parseTarget } from '../net/policy.ts';
import type { TargetPolicy } from '../net/policy.ts';
import { resolveTarget } from '../net/resolve.ts';
import type { Lookup } from '../net/resolve.ts';
import { discoverOidc } from './discover.ts';

export interface IssuerKeys {
  kind: 'issuer-keys';
  issuer: string;
  found: boolean;
  discoveryUrl?: string;
  /** The `issuer` the metadata declares; it should equal the one asked for. */
  declaredIssuer?: string;
  issuerMatches?: boolean;
  jwksUri?: string;
  jwks?: Record<string, unknown>;
  error?: string;
}

export async function fetchIssuerKeys(issuer: string, options: { policy: TargetPolicy; lookup?: Lookup; budgetMs?: number }): Promise<IssuerKeys> {
  const target = parseTarget(issuer, options.policy);
  const pinned = await resolveTarget(target, { lookup: options.lookup });
  const deadline = Date.now() + (options.budgetMs ?? 20_000);
  const { summary, jwks } = await discoverOidc(target.url, pinned, options.policy, { lookup: options.lookup, deadline, includeFullPath: true, exactIssuer: true });
  return {
    kind: 'issuer-keys',
    issuer: target.url.href.replace(/\/$/, ''),
    found: summary.found,
    discoveryUrl: summary.discoveryUrl,
    declaredIssuer: summary.issuer,
    issuerMatches: summary.issuerMatches,
    jwksUri: summary.jwksUri,
    jwks,
    error: summary.found ? summary.jwksError : `No OpenID Connect metadata at ${summary.tried[0]?.url} (${summary.tried[0]?.result}).`,
  };
}
