/**
 * In-browser JWS signing and verification for the token checker and the login lab.
 *
 * Browsers don't offer ML-DSA through Web Crypto yet, so ML-DSA uses
 * @noble/post-quantum (audited, pure TypeScript). ES256 and RS256 use the
 * browser's built-in Web Crypto. The token format follows RFC 7515 (JWS) and
 * RFC 9964 (ML-DSA for JOSE): "pure" ML-DSA with an empty context string.
 *
 * `verifyJwt` applies the same rules, in the same order, as the server-side
 * verifier in packages/token-kit. A test checks that both reach the same
 * verdict for every attack in the playground.
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import type { SigningAlg } from '@pq-oidc/token-kit/algorithms';
import { base64urlToBytes, base64urlToJson, bytesToBase64url, jsonToBase64url } from '@pq-oidc/token-kit/base64url';

export const ML_DSA = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 } as const;
export type MlDsaAlg = keyof typeof ML_DSA;

export function isMlDsa(alg: string): alg is MlDsaAlg {
  return Object.hasOwn(ML_DSA, alg);
}

/** A public key as it appears in a JWKS. ML-DSA keys use the AKP key type from RFC 9964. */
export type PublicJwk =
  | { kty: 'AKP'; alg: MlDsaAlg; kid: string; pub: string }
  | (JsonWebKey & { kid: string; alg: 'ES256' | 'RS256' });

export type LabKey =
  | { alg: 'ES256' | 'RS256'; kid: string; privateKey: CryptoKey; publicJwk: PublicJwk }
  | { alg: MlDsaAlg; kid: string; seed: Uint8Array; secretKey: Uint8Array; publicJwk: PublicJwk };

const WEB_CRYPTO_PARAMS = {
  ES256: {
    generate: { name: 'ECDSA', namedCurve: 'P-256' } as EcKeyGenParams,
    import: { name: 'ECDSA', namedCurve: 'P-256' } as EcKeyImportParams,
    sign: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
  },
  RS256: {
    generate: {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    } as RsaHashedKeyGenParams,
    import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as RsaHashedImportParams,
    sign: { name: 'RSASSA-PKCS1-v1_5' } as AlgorithmIdentifier,
  },
};

export async function generateKey(alg: SigningAlg, kid: string = alg.toLowerCase()): Promise<LabKey> {
  if (isMlDsa(alg)) {
    // RFC 9964 represents an ML-DSA private key by its 32-byte seed.
    return mlDsaKeyFromSeed(alg, crypto.getRandomValues(new Uint8Array(32)), kid);
  }
  const params = WEB_CRYPTO_PARAMS[alg];
  const pair = (await crypto.subtle.generateKey(params.generate, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return {
    alg,
    kid,
    privateKey: pair.privateKey,
    publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, n: jwk.n, e: jwk.e, alg, kid },
  };
}

export function mlDsaKeyFromSeed(alg: MlDsaAlg, seed: Uint8Array, kid: string): LabKey {
  const { secretKey, publicKey } = ML_DSA[alg].keygen(seed);
  return { alg, kid, seed, secretKey, publicJwk: { kty: 'AKP', alg, kid, pub: bytesToBase64url(publicKey) } };
}

const encoder = new TextEncoder();

/** Signs `payload` as a compact JWS. `header` members are added to (and may override) alg/kid/typ. */
export async function signJwt(key: LabKey, payload: object, header: Record<string, unknown> = {}): Promise<string> {
  const protectedHeader = { alg: key.alg, kid: key.kid, typ: 'JWT', ...header };
  const signingInput = `${jsonToBase64url(protectedHeader)}.${jsonToBase64url(payload)}`;
  const signature = await signBytes(key, encoder.encode(signingInput));
  return `${signingInput}.${bytesToBase64url(signature)}`;
}

export async function signBytes(key: LabKey, data: Uint8Array): Promise<Uint8Array> {
  if (key.alg === 'ES256' || key.alg === 'RS256') {
    // Web Crypto returns ECDSA signatures as raw r || s, which is exactly the JWS format.
    return new Uint8Array(await crypto.subtle.sign(WEB_CRYPTO_PARAMS[key.alg].sign, key.privateKey, data as BufferSource));
  }
  if (!('secretKey' in key)) throw new Error('Unexpected key type');
  return ML_DSA[key.alg].sign(data, key.secretKey);
}

/** Checks a signature with a public JWK. Returns false (never throws) for a wrong signature. */
export async function verifySignature(jwk: PublicJwk, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  try {
    if ('pub' in jwk && isMlDsa(jwk.alg)) {
      return ML_DSA[jwk.alg].verify(signature, data, base64urlToBytes(jwk.pub));
    }
    const alg = jwk.alg as 'ES256' | 'RS256';
    const params = WEB_CRYPTO_PARAMS[alg];
    const key = await crypto.subtle.importKey('jwk', jwk, params.import, false, ['verify']);
    return await crypto.subtle.verify(params.sign, key, signature as BufferSource, data as BufferSource);
  } catch {
    return false;
  }
}

export type RejectionCode =
  | 'malformed'
  | 'unsecured'
  | 'alg-not-allowed'
  | 'unknown-key'
  | 'bad-signature'
  | 'expired'
  | 'claim-mismatch';

export type VerifyResult =
  | { ok: true; header: Record<string, unknown>; payload: Record<string, unknown> }
  | { ok: false; code: RejectionCode; reason: string };

export interface VerifyOptions {
  issuer: string;
  audience: string;
  /** The algorithm allowlist. */
  algorithms: string[];
  /** Current time in seconds (injectable for tests). */
  now?: number;
}

export interface ParsedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}

export function parseJwt(token: string): ParsedJwt | undefined {
  const parts = token.trim().split('.');
  if (parts.length !== 3) return undefined;
  const [h, p, s] = parts as [string, string, string];
  try {
    return {
      header: base64urlToJson(h),
      payload: base64urlToJson(p),
      signingInput: encoder.encode(`${h}.${p}`),
      signature: base64urlToBytes(s),
    };
  } catch {
    return undefined;
  }
}

const reject = (code: RejectionCode, reason: string): VerifyResult => ({ ok: false, code, reason });

/**
 * The careful verifier: the same checks the demo apps run on the server.
 *  1. Refuse unsigned tokens.
 *  2. Refuse algorithms outside the allowlist.
 *  3. Take the key from the provider's JWKS only (never from the token), matched by kid AND alg.
 *  4. Check the signature, then issuer, audience and expiry.
 */
export async function verifyJwt(token: string, jwks: PublicJwk[], options: VerifyOptions): Promise<VerifyResult> {
  const jwt = parseJwt(token);
  if (!jwt) return reject('malformed', 'The token is not a well-formed JWT.');
  const { header, payload } = jwt;
  const alg = header.alg;

  if (typeof alg !== 'string' || alg.toLowerCase() === 'none') {
    return reject('unsecured', 'The token is not signed (alg "none"), so anyone could have written it.');
  }
  if (!options.algorithms.includes(alg)) {
    return reject('alg-not-allowed', `The token is signed with ${alg}, but this app only accepts ${options.algorithms.join(', ')}.`);
  }
  const key = jwks.find((k) => k.kid === header.kid && k.alg === alg);
  if (!key) return reject('unknown-key', 'None of the trusted public keys matches this token.');
  if (!(await verifySignature(key, jwt.signingInput, jwt.signature))) {
    return reject('bad-signature', 'The signature does not match: the token was altered or forged.');
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || typeof payload.iat !== 'number' || typeof payload.sub !== 'string') {
    return reject('claim-mismatch', 'The token is missing a required claim (sub, iat or exp).');
  }
  if (payload.iss !== options.issuer) return reject('claim-mismatch', 'The "iss" claim failed validation (unexpected issuer).');
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(options.audience)) {
    return reject('claim-mismatch', 'The "aud" claim failed validation (token was issued to a different app).');
  }
  if (payload.exp <= now) return reject('expired', 'The token has expired.');
  return { ok: true, header, payload };
}

/**
 * Re-signs an existing JWT with `key`, keeping its exact claims bytes and
 * header (only "alg" changes). Used to prove the size projection is exact.
 */
export async function resignJwt(key: LabKey, token: string): Promise<string> {
  const [encodedHeader = '', encodedPayload = ''] = token.trim().split('.');
  const header = base64urlToJson(encodedHeader);
  const signingInput = `${jsonToBase64url({ ...header, alg: key.alg })}.${encodedPayload}`;
  const signature = await signBytes(key, encoder.encode(signingInput));
  return `${signingInput}.${bytesToBase64url(signature)}`;
}
