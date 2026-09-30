/**
 * Classic JWT attacks, each built with real cryptography, plus a deliberately
 * naive verifier that makes mistakes real JWT libraries have shipped with
 * (for example CVE-2015-9235, algorithm confusion in node-jsonwebtoken).
 */
import { bytesToBase64url, jsonToBase64url } from '@pq-oidc/token-kit/base64url';
import { generateKey, parseJwt, signJwt, verifySignature } from './jws.ts';
import type { LabKey, PublicJwk, VerifyResult } from './jws.ts';

export interface AttackContext {
  /** The provider's real signing key (the app trusts its public half). */
  providerKey: LabKey;
  issuer: string;
  audience: string;
  /** The honest claims the provider issued to the victim. */
  claims: Record<string, unknown>;
}

export interface Attack {
  id: string;
  title: string;
  /** What the attacker does, in plain language. */
  story: string;
  /** Which rule stops it. */
  defense: string;
  build: (ctx: AttackContext) => Promise<string>;
}

const now = () => Math.floor(Date.now() / 1000);
const adminClaims = (ctx: AttackContext) => ({ ...ctx.claims, sub: 'admin', name: 'Mallory (pretending to be admin)' });

async function hmacSha256(secret: Uint8Array, data: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', secret as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
}

/** The "secret" a confused verifier would use for HS256: the public key's bytes. */
export function publicKeyAsHmacSecret(jwk: PublicJwk): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(jwk));
}

export const ATTACKS: Attack[] = [
  {
    id: 'honest',
    title: 'Honest token',
    story: 'The token exactly as the provider issued it. Both verifiers should accept this one.',
    defense: 'Nothing to stop: the signature, issuer, audience and expiry are all valid.',
    build: (ctx) => signJwt(ctx.providerKey, ctx.claims),
  },
  {
    id: 'edit-claims',
    title: 'Edit the claims',
    story: 'Mallory decodes the token, changes "sub" to admin and re-encodes it, keeping the original signature.',
    defense: 'The signature covers every byte of the header and payload, so any edit breaks it.',
    build: async (ctx) => {
      const [header, , signature] = (await signJwt(ctx.providerKey, ctx.claims)).split('.');
      return `${header}.${jsonToBase64url(adminClaims(ctx))}.${signature}`;
    },
  },
  {
    id: 'alg-none',
    title: 'Remove the signature',
    story: 'Mallory writes her own claims, sets the header to {"alg": "none"} and leaves the signature empty.',
    defense: 'Unsigned tokens are refused outright, and "none" is never on the allowlist.',
    build: async (ctx) => `${jsonToBase64url({ alg: 'none', typ: 'JWT' })}.${jsonToBase64url(adminClaims(ctx))}.`,
  },
  {
    id: 'alg-confusion',
    title: 'Algorithm confusion',
    story:
      'The public key is public. Mallory sets "alg" to HS256 (a shared-secret algorithm) and signs with the public key as the secret.',
    defense: 'The app only accepts its allowlisted asymmetric algorithms, and each key is bound to one algorithm.',
    build: async (ctx) => {
      const input = `${jsonToBase64url({ alg: 'HS256', kid: ctx.providerKey.kid, typ: 'JWT' })}.${jsonToBase64url(adminClaims(ctx))}`;
      const mac = await hmacSha256(publicKeyAsHmacSecret(ctx.providerKey.publicJwk), input);
      return `${input}.${bytesToBase64url(mac)}`;
    },
  },
  {
    id: 'embedded-key',
    title: 'Bring your own key',
    story:
      'Mallory generates her own ML-DSA-65 key, signs admin claims with it, and puts her public key in the token header ("jwk").',
    defense: 'Keys come only from the provider’s published JWKS. Keys inside the token are ignored.',
    build: async (ctx) => {
      const mallory = await generateKey('ML-DSA-65', ctx.providerKey.kid);
      return signJwt(mallory, adminClaims(ctx), { jwk: mallory.publicJwk });
    },
  },
  {
    id: 'expired',
    title: 'Replay an old token',
    story: 'Mallory found a genuine token in an old log file. It was valid yesterday.',
    defense: 'The "exp" claim is checked on every request.',
    build: (ctx) => signJwt(ctx.providerKey, { ...ctx.claims, iat: now() - 90_000, exp: now() - 86_400 }),
  },
  {
    id: 'wrong-audience',
    title: 'Token for another app',
    story: 'Mallory runs a different app on the same provider. She replays a token that users gave to her app.',
    defense: 'The "aud" claim must name this app.',
    build: (ctx) => signJwt(ctx.providerKey, { ...ctx.claims, aud: 'mallorys-quiz-app' }),
  },
];

/**
 * A verifier with three real-world mistakes:
 *  - it trusts the token's own "alg" header, including "none",
 *  - it trusts a key embedded in the token header,
 *  - for HS256 it uses the public key as the HMAC secret,
 * and it skips issuer, audience and expiry checks.
 */
export async function naiveVerify(token: string, jwks: PublicJwk[]): Promise<VerifyResult> {
  const jwt = parseJwt(token);
  if (!jwt) return { ok: false, code: 'malformed', reason: 'The token is not a well-formed JWT.' };
  const { header, payload } = jwt;

  if (typeof header.alg === 'string' && header.alg.toLowerCase() === 'none') {
    return { ok: true, header, payload };
  }
  const key = (header.jwk as PublicJwk | undefined) ?? jwks.find((k) => k.kid === header.kid) ?? jwks[0];
  if (!key) return { ok: false, code: 'unknown-key', reason: 'No key found.' };

  if (header.alg === 'HS256') {
    const expected = await hmacSha256(publicKeyAsHmacSecret(key), new TextDecoder().decode(jwt.signingInput));
    const valid = bytesToBase64url(expected) === bytesToBase64url(jwt.signature);
    return valid
      ? { ok: true, header, payload }
      : { ok: false, code: 'bad-signature', reason: 'The HMAC does not match.' };
  }
  const valid = await verifySignature({ ...key, alg: header.alg } as PublicJwk, jwt.signingInput, jwt.signature);
  return valid
    ? { ok: true, header, payload }
    : { ok: false, code: 'bad-signature', reason: 'The signature does not match: the token was altered or forged.' };
}

/** Splits a token into its three parts for colour-coded display. */
export function tokenParts(token: string): { header: string; payload: string; signature: string } {
  const [header = '', payload = '', signature = ''] = token.split('.');
  return { header, payload, signature };
}

