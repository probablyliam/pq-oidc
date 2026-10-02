/**
 * Checks a JWT's signature against a set of public keys (a JWKS), for
 * analysis rather than authentication. Runs in browsers and in Node, on Web
 * Crypto plus @noble/post-quantum for ML-DSA, so a pasted token never has to
 * leave the page (ADR 0010).
 *
 * The rules that keep an analyzer from being fooled:
 *  - "none" is reported as unsigned, never as valid.
 *  - HMAC algorithms are never checked against published keys. Using a public
 *    key as an HMAC secret is the algorithm-confusion attack.
 *  - Keys come only from the JWKS passed in. Key material in the token's own
 *    header (jwk, jku, x5u, x5c) is not read by this function at all.
 *  - A key is only tried if its type fits the algorithm, and if it declares an
 *    "alg", only for that algorithm.
 *  - This function performs no network requests.
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { base64urlToBytes, base64urlToJson } from './base64url.ts';
import { describeJwsAlg } from './jose.ts';
import type { JwsAlg } from './jose.ts';
import { describeKey } from './readiness.ts';
import type { KeySummary } from './readiness.ts';

export type Jwk = Record<string, unknown>;

export type SignatureCheck =
  | { status: 'valid'; key: KeySummary }
  | { status: 'invalid'; detail: string; triedKeys: number }
  | { status: 'unsigned'; detail: string }
  | { status: 'not-verifiable'; reason: 'symmetric' | 'no-matching-key' | 'unsupported-algorithm' | 'malformed'; detail: string };

const ML_DSA = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 } as const;
const encoder = new TextEncoder();

/** Does this published key fit the token's algorithm? */
function keyFits(key: Jwk, alg: JwsAlg): boolean {
  if (key.use === 'enc') return false;
  if (typeof key.alg === 'string' && key.alg !== alg.alg) return false;
  switch (alg.kind) {
    case 'rsa-pkcs1':
    case 'rsa-pss':
      return key.kty === 'RSA' && typeof key.n === 'string' && typeof key.e === 'string';
    case 'ecdsa':
      return key.kty === 'EC' && key.crv === alg.curve && typeof key.x === 'string' && typeof key.y === 'string';
    case 'eddsa':
      return key.kty === 'OKP' && key.crv === 'Ed25519' && alg.curve === 'Ed25519' && typeof key.x === 'string';
    case 'ml-dsa':
      // RFC 9964: an AKP key always names its algorithm.
      return key.kty === 'AKP' && key.alg === alg.alg && typeof key.pub === 'string';
    default:
      return false;
  }
}

async function verifyWithKey(key: Jwk, alg: JwsAlg, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (alg.kind === 'ml-dsa') {
    return ML_DSA[alg.alg as keyof typeof ML_DSA].verify(signature, data, base64urlToBytes(String(key.pub)));
  }
  const subtle = globalThis.crypto.subtle;
  // Web Crypto wants views over a plain ArrayBuffer; these always are.
  const sig = signature as Uint8Array<ArrayBuffer>;
  const message = data as Uint8Array<ArrayBuffer>;
  // Only the public members are imported, so stray "alg", "use" or private fields in the JWK cannot influence the import.
  if (alg.kind === 'rsa-pkcs1' || alg.kind === 'rsa-pss') {
    const name = alg.kind === 'rsa-pss' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5';
    const imported = await subtle.importKey('jwk', { kty: 'RSA', n: String(key.n), e: String(key.e) }, { name, hash: alg.hash! }, false, ['verify']);
    return subtle.verify(alg.kind === 'rsa-pss' ? { name, saltLength: Number(alg.hash!.slice(4)) / 8 } : { name }, imported, sig, message);
  }
  if (alg.kind === 'ecdsa') {
    const imported = await subtle.importKey('jwk', { kty: 'EC', crv: alg.curve, x: String(key.x), y: String(key.y) }, { name: 'ECDSA', namedCurve: alg.curve! }, false, ['verify']);
    return subtle.verify({ name: 'ECDSA', hash: alg.hash! }, imported, sig, message);
  }
  const imported = await subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: String(key.x) }, { name: 'Ed25519' }, false, ['verify']);
  return subtle.verify({ name: 'Ed25519' }, imported, sig, message);
}

export async function checkSignature(token: string, jwks: { keys?: unknown }): Promise<SignatureCheck> {
  const parts = token.trim().split('.');
  if (parts.length !== 3) return { status: 'not-verifiable', reason: 'malformed', detail: 'A signed JWT has three dot-separated parts.' };
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];

  let header: Record<string, unknown>;
  let signature: Uint8Array;
  try {
    header = base64urlToJson(encodedHeader);
    signature = base64urlToBytes(encodedSignature);
  } catch {
    return { status: 'not-verifiable', reason: 'malformed', detail: 'The header or signature is not valid base64url.' };
  }

  const alg = describeJwsAlg(header.alg);
  if (alg.kind === 'none') {
    return { status: 'unsigned', detail: 'The header says alg "none": there is no signature to check, so anyone could have written this token.' };
  }
  if (alg.kind === 'hmac') {
    return {
      status: 'not-verifiable',
      reason: 'symmetric',
      detail: `${alg.alg} is a keyed hash made with a secret shared between the issuer and the app. It cannot be checked with published keys, and a public key must never be used as that secret.`,
    };
  }
  const supported = alg.kind === 'rsa-pkcs1' || alg.kind === 'rsa-pss' || alg.kind === 'ml-dsa' || (alg.kind === 'ecdsa' && alg.curve !== undefined) || (alg.kind === 'eddsa' && alg.curve === 'Ed25519');
  if (!supported) {
    return { status: 'not-verifiable', reason: 'unsupported-algorithm', detail: `This page cannot check ${alg.alg || 'a token with no algorithm'} signatures.` };
  }

  const published = (Array.isArray(jwks.keys) ? jwks.keys : []).filter((k): k is Jwk => typeof k === 'object' && k !== null);
  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  // With a key ID, only that key is the right one. Without one, any key of a fitting type may be.
  const candidates = published.filter((k) => keyFits(k, alg) && (kid === undefined || k.kid === kid)).slice(0, 12);
  if (candidates.length === 0) {
    const named = kid !== undefined && published.some((k) => k.kid === kid);
    return {
      status: 'not-verifiable',
      reason: 'no-matching-key',
      detail: named
        ? `The key set has a key with ID "${kid}", but it is not a key for ${alg.alg}. A key is never used with an algorithm it was not published for.`
        : kid !== undefined
          ? `None of the ${published.length} published keys has the ID "${kid}" named in the token.`
          : `None of the ${published.length} published keys is a key for ${alg.alg}.`,
    };
  }

  const data = encoder.encode(`${encodedHeader}.${encodedPayload}`);
  for (const key of candidates) {
    try {
      if (await verifyWithKey(key, alg, data, signature)) return { status: 'valid', key: describeKey(key) };
    } catch {
      // A key that cannot be imported is a key that does not verify this token.
    }
  }
  return {
    status: 'invalid',
    triedKeys: candidates.length,
    detail: `The signature does not verify with ${candidates.length === 1 ? 'the matching published key' : `any of the ${candidates.length} matching published keys`}. The token was altered, or was not signed by this issuer.`,
  };
}
