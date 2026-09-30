import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
import type { JWK } from 'jose';

/**
 * The provider holds one signing key per algorithm it offers. During a
 * migration both keys are live: the classical key keeps legacy apps working
 * while clients move to the post-quantum key one at a time.
 */
export const SIGNING_ALGS = ['ES256', 'ML-DSA-65'] as const;
export type ProviderSigningAlg = (typeof SIGNING_ALGS)[number];

export interface PrivateJwks {
  keys: JWK[];
}

/**
 * Generates a fresh private key per algorithm.
 *
 * The key ID (`kid`) is the RFC 7638 thumbprint. For ML-DSA keys ("kty": "AKP")
 * RFC 9964 defines which members go into the thumbprint.
 *
 * Keys generated here live only in memory. That is fine for a demo with one
 * replica, but a real deployment loads them from a secret store (see loadSigningKeys).
 */
export async function generateSigningKeys(): Promise<PrivateJwks> {
  const keys = await Promise.all(
    SIGNING_ALGS.map(async (alg) => {
      const { privateKey } = await generateKeyPair(alg, { extractable: true });
      const jwk = await exportJWK(privateKey);
      return { ...jwk, alg, use: 'sig', kid: await calculateJwkThumbprint(jwk) };
    }),
  );
  return { keys };
}

/**
 * Loads a private JWKS from JSON (for example a mounted Kubernetes Secret) and
 * checks it has exactly what the provider needs.
 */
export function loadSigningKeys(json: string): PrivateJwks {
  const parsed: unknown = JSON.parse(json);
  if (typeof parsed !== 'object' || parsed === null || !Array.isArray((parsed as PrivateJwks).keys)) {
    throw new Error('Signing keys must be a JWKS object: { "keys": [...] }');
  }
  const { keys } = parsed as PrivateJwks;
  for (const alg of SIGNING_ALGS) {
    const key = keys.find((k) => k.alg === alg);
    if (!key) throw new Error(`Signing keys are missing a key for ${alg}`);
    if (!key.kid) throw new Error(`The ${alg} signing key needs a "kid"`);
    const hasPrivatePart = key.kty === 'AKP' ? Boolean(key.priv) : Boolean(key.d);
    if (!hasPrivatePart) throw new Error(`The ${alg} signing key must be a private key`);
  }
  return { keys };
}
