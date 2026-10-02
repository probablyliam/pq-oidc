/**
 * Post-quantum readiness report for any OpenID Connect provider, built from its
 * public discovery document and JWKS. Pure functions: the browser lab and the
 * CLI (scripts/check-issuer.ts) both fetch the documents and call analyzeProvider.
 */
import { ALGORITHMS } from './algorithms.ts';
import { base64urlLength } from './limits.ts';

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface Check {
  id: string;
  status: CheckStatus;
  label: string;
  detail: string;
}

export interface KeySummary {
  kid: string | undefined;
  kty: string;
  alg: string | undefined;
  use: string | undefined;
  /** Human-readable strength, e.g. "RSA 2048-bit", "P-256", "ML-DSA-65". */
  strength: string;
  quantumSafe: boolean;
  jsonBytes: number;
}

export interface ProviderReport {
  issuer: string;
  idTokenAlgs: string[];
  keys: KeySummary[];
  verdict: 'ready' | 'partial' | 'not-ready';
  jwksBytes: number;
  /** ID token algorithms a quantum computer breaks (RSA and elliptic-curve signatures). */
  vulnerableAlgs: string[];
  /** JWKS size after publishing one ML-DSA-65 key next to the existing keys. */
  jwksBytesWithMlDsa65: number;
  checks: Check[];
}

type Json = Record<string, unknown>;

/** Post-quantum signature algorithms with registered or proposed JOSE names. */
export function isQuantumSafeAlg(alg: unknown): boolean {
  return typeof alg === 'string' && /^(ML-DSA|SLH-DSA|FN-DSA)/i.test(alg);
}

/**
 * Shared-secret (HMAC) algorithms. Shor's algorithm does not apply to them, so a
 * quantum computer can't forge them, but they aren't public-key signatures:
 * every app that verifies the token holds the secret and could mint one too.
 */
export function isSymmetricAlg(alg: unknown): boolean {
  return typeof alg === 'string' && /^HS\d+$/.test(alg);
}

/** Public-key signature algorithms that Shor's algorithm breaks (RSA and elliptic curves). */
export function isQuantumVulnerableAlg(alg: unknown): boolean {
  return typeof alg === 'string' && alg.toLowerCase() !== 'none' && !isQuantumSafeAlg(alg) && !isSymmetricAlg(alg);
}

const EC_CURVES: Record<string, string> = { 'P-256': 'P-256', 'P-384': 'P-384', 'P-521': 'P-521' };

export function describeKey(jwk: Json): KeySummary {
  const kty = String(jwk.kty ?? '?');
  const alg = typeof jwk.alg === 'string' ? jwk.alg : undefined;
  let strength = kty;
  if (kty === 'RSA' && typeof jwk.n === 'string') {
    // Modulus length in bits, from the base64url-encoded modulus.
    const bytes = Math.floor((jwk.n.replace(/=+$/, '').length * 3) / 4);
    strength = `RSA ${Math.round((bytes * 8) / 256) * 256}-bit`;
  } else if (kty === 'EC') {
    strength = EC_CURVES[String(jwk.crv)] ?? `EC ${String(jwk.crv)}`;
  } else if (kty === 'OKP') {
    strength = String(jwk.crv ?? 'OKP');
  } else if (kty === 'AKP') {
    strength = alg ?? 'AKP';
  } else if (kty === 'oct') {
    strength = 'Shared secret';
  }
  return {
    kid: typeof jwk.kid === 'string' ? jwk.kid : undefined,
    kty,
    alg,
    use: typeof jwk.use === 'string' ? jwk.use : undefined,
    strength,
    quantumSafe: kty === 'AKP' && isQuantumSafeAlg(alg),
    jsonBytes: JSON.stringify(jwk).length,
  };
}

/** Size of a published ML-DSA-65 JWK: the base64url public key plus {"kty","use","kid" (43-char thumbprint),"alg"} (104 bytes). */
const ML_DSA_65_JWK_BYTES = base64urlLength(ALGORITHMS['ML-DSA-65'].publicKeyBytes) + 104;

export function analyzeProvider(discovery: Json, jwks: Json, jwksBytes: number): ProviderReport {
  const idTokenAlgs = Array.isArray(discovery.id_token_signing_alg_values_supported)
    ? discovery.id_token_signing_alg_values_supported.map(String)
    : [];
  const rawKeys = Array.isArray(jwks.keys) ? (jwks.keys as Json[]) : [];
  const keys = rawKeys.map(describeKey);
  const signingKeys = keys.filter((k) => k.use !== 'enc');

  const pqAlgs = idTokenAlgs.filter(isQuantumSafeAlg);
  const vulnerableAlgs = idTokenAlgs.filter(isQuantumVulnerableAlg);
  const symmetricAlgs = idTokenAlgs.filter(isSymmetricAlg);
  const pqKeys = signingKeys.filter((k) => k.quantumSafe);
  const verdict: ProviderReport['verdict'] =
    pqAlgs.length > 0 && pqKeys.length > 0
      ? signingKeys.every((k) => k.quantumSafe)
        ? 'ready'
        : 'partial'
      : 'not-ready';

  const checks: Check[] = [];
  checks.push(
    pqAlgs.length > 0
      ? { id: 'pq-algs', status: 'pass', label: 'Offers post-quantum ID token signatures', detail: pqAlgs.join(', ') }
      : {
          id: 'pq-algs',
          status: 'fail',
          label: 'No post-quantum ID token signatures',
          detail:
            vulnerableAlgs.length > 0
              ? `Its public-key signatures (${vulnerableAlgs.join(', ')}) can be forged with a large quantum computer.${
                  symmetricAlgs.length > 0
                    ? ` It also lists ${symmetricAlgs.join(', ')}, a shared-secret method that quantum computers don't break but that only works when the app holds the provider's secret.`
                    : ''
                }`
              : `Lists ${idTokenAlgs.join(', ') || 'no algorithms'}; none is a post-quantum signature.`,
        },
  );
  checks.push(
    pqKeys.length > 0
      ? {
          id: 'pq-keys',
          status: 'pass',
          label: 'Publishes post-quantum keys',
          detail: `${pqKeys.length} of ${signingKeys.length} signing keys are ML-DSA (RFC 9964 "AKP" keys).`,
        }
      : {
          id: 'pq-keys',
          status: 'fail',
          label: 'No post-quantum keys in the JWKS',
          detail: `All ${signingKeys.length} signing keys are classical (${[...new Set(signingKeys.map((k) => k.strength))].join(', ')}).`,
        },
  );

  // Browser sign-in checks only apply to providers with an authorization endpoint.
  // Machine-identity issuers (e.g. GitHub Actions) only mint tokens for workloads.
  if (typeof discovery.authorization_endpoint === 'string') {
    const pkce = discovery.code_challenge_methods_supported;
    checks.push(
      Array.isArray(pkce) && pkce.includes('S256')
        ? { id: 'pkce', status: 'pass', label: 'Advertises PKCE (S256)', detail: 'Required by OAuth 2.1 for every client.' }
        : {
            id: 'pkce',
            status: 'warn',
            label: 'PKCE (S256) not advertised',
            detail: 'code_challenge_methods_supported is missing or lacks S256. OAuth 2.1 requires PKCE.',
          },
    );

    const responseTypes = Array.isArray(discovery.response_types_supported)
      ? discovery.response_types_supported.map(String)
      : [];
    const implicit = responseTypes.filter((t) => t.split(' ').includes('token'));
    checks.push(
      implicit.length === 0
        ? { id: 'implicit', status: 'pass', label: 'No implicit flow', detail: 'Access tokens are never returned in the URL.' }
        : {
            id: 'implicit',
            status: 'warn',
            label: 'Still offers the implicit flow',
            detail: `response_types_supported includes ${implicit.map((t) => `"${t}"`).join(', ')}, which OAuth 2.1 removes.`,
          },
    );
  } else {
    checks.push({
      id: 'no-browser-flow',
      status: 'info',
      label: 'Machine-identity issuer',
      detail: 'No authorization endpoint: this issuer mints tokens for workloads, not browser sign-ins.',
    });
  }

  if (idTokenAlgs.some((a) => a.toLowerCase() === 'none')) {
    checks.push({
      id: 'alg-none',
      status: 'fail',
      label: 'Allows unsigned ID tokens',
      detail: '"none" is listed in id_token_signing_alg_values_supported.',
    });
  }

  return {
    issuer: String(discovery.issuer ?? ''),
    idTokenAlgs,
    vulnerableAlgs,
    keys,
    verdict,
    jwksBytes,
    jwksBytesWithMlDsa65: jwksBytes + ML_DSA_65_JWK_BYTES + 1,
    checks,
  };
}

/** Builds the discovery URL for an issuer, tolerating trailing slashes and pasted discovery URLs. */
export function discoveryUrl(issuer: string): string {
  const trimmed = issuer.trim().replace(/\/+$/, '');
  if (trimmed.endsWith('/.well-known/openid-configuration')) return trimmed;
  return `${trimmed}/.well-known/openid-configuration`;
}
