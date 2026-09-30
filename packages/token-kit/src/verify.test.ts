import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { JSONWebKeySet, JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { measureJwt } from './measure.ts';
import { jsonToBase64url } from './base64url.ts';
import { TokenRejectedError, verifyIdToken } from './verify.ts';

const ISSUER = 'https://issuer.example';
const AUDIENCE = 'demo-app';

type Signer = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

let ecKey: Signer;
let pqKey: Signer;
let jwks: JSONWebKeySet;

beforeAll(async () => {
  const ec = await generateKeyPair('ES256', { extractable: true });
  const pq = await generateKeyPair('ML-DSA-65', { extractable: true });
  ecKey = ec.privateKey;
  pqKey = pq.privateKey;
  jwks = {
    keys: [
      { ...(await exportJWK(ec.publicKey)), kid: 'ec-1', alg: 'ES256' },
      { ...(await exportJWK(pq.publicKey)), kid: 'pq-1', alg: 'ML-DSA-65' },
    ],
  };
});

function sign(key: Signer, alg: string, kid: string, claims: Record<string, unknown> = {}) {
  return new SignJWT({ name: 'Alice', ...claims })
    .setProtectedHeader({ alg, kid, typ: 'JWT' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject('alice')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key);
}

async function rejectionCode(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(TokenRejectedError);
    return (error as TokenRejectedError).code;
  }
  throw new Error('Expected the token to be rejected');
}

describe('verifyIdToken', () => {
  const both = { issuer: ISSUER, audience: AUDIENCE, algorithms: ['ES256', 'ML-DSA-65'] };

  it('accepts a valid ES256 token', async () => {
    const token = await sign(ecKey, 'ES256', 'ec-1');
    const { payload, header } = await verifyIdToken(token, createLocalJWKSet(jwks), both);
    expect(header.alg).toBe('ES256');
    expect(payload.sub).toBe('alice');
  });

  it('accepts a valid ML-DSA-65 token', async () => {
    const token = await sign(pqKey, 'ML-DSA-65', 'pq-1');
    const { header } = await verifyIdToken(token, createLocalJWKSet(jwks), both);
    expect(header.alg).toBe('ML-DSA-65');
  });

  it('lets a legacy app refuse post-quantum tokens through its allowlist', async () => {
    const token = await sign(pqKey, 'ML-DSA-65', 'pq-1');
    const legacy = { ...both, algorithms: ['ES256'] };
    expect(await rejectionCode(verifyIdToken(token, createLocalJWKSet(jwks), legacy))).toBe('alg-not-allowed');
  });

  it('rejects a token whose payload was edited after signing', async () => {
    const token = await sign(pqKey, 'ML-DSA-65', 'pq-1');
    const [header, , signature] = token.split('.');
    const forgedPayload = jsonToBase64url({ ...measureJwt(token).payload, sub: 'admin' });
    const forged = `${header}.${forgedPayload}.${signature}`;
    expect(await rejectionCode(verifyIdToken(forged, createLocalJWKSet(jwks), both))).toBe('bad-signature');
  });

  it('rejects an unsigned token (alg "none")', async () => {
    const header = jsonToBase64url({ alg: 'none', typ: 'JWT' });
    const payload = jsonToBase64url({ iss: ISSUER, aud: AUDIENCE, sub: 'admin', iat: 1, exp: 9_999_999_999 });
    expect(await rejectionCode(verifyIdToken(`${header}.${payload}.`, createLocalJWKSet(jwks), both))).toBe(
      'unsecured',
    );
  });

  it('rejects algorithm confusion (HS256 signed with the public key as the secret)', async () => {
    const publicJwk = jwks.keys[0] as JWK;
    const secret = new TextEncoder().encode(JSON.stringify(publicJwk));
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256', kid: 'ec-1' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('admin')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(secret);
    expect(await rejectionCode(verifyIdToken(token, createLocalJWKSet(jwks), both))).toBe('alg-not-allowed');
  });

  it('ignores an attacker key embedded in the token header', async () => {
    const attacker = await generateKeyPair('ML-DSA-65', { extractable: true });
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'ML-DSA-65', kid: 'pq-1', jwk: await exportJWK(attacker.publicKey) })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('admin')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(attacker.privateKey);
    expect(await rejectionCode(verifyIdToken(token, createLocalJWKSet(jwks), both))).toBe('bad-signature');
  });

  it('rejects a token signed by a key the app does not trust', async () => {
    const stranger = await generateKeyPair('ES256');
    const token = await sign(stranger.privateKey, 'ES256', 'someone-else');
    expect(await rejectionCode(verifyIdToken(token, createLocalJWKSet(jwks), both))).toBe('unknown-key');
  });

  it('rejects expired tokens', async () => {
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: 'ec-1' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('alice')
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(ecKey);
    expect(await rejectionCode(verifyIdToken(token, createLocalJWKSet(jwks), both))).toBe('expired');
  });

  it('rejects a token issued to a different app', async () => {
    const token = await sign(ecKey, 'ES256', 'ec-1');
    const otherApp = { ...both, audience: 'some-other-app' };
    expect(await rejectionCode(verifyIdToken(token, createLocalJWKSet(jwks), otherApp))).toBe('claim-mismatch');
  });

  it('rejects a token from a different login attempt (nonce)', async () => {
    const token = await sign(ecKey, 'ES256', 'ec-1', { nonce: 'first-login' });
    const options = { ...both, nonce: 'second-login' };
    expect(await rejectionCode(verifyIdToken(token, createLocalJWKSet(jwks), options))).toBe('claim-mismatch');
  });
});

describe('measureJwt', () => {
  it('reports the real signature sizes from FIPS 204 and RFC 7518', async () => {
    expect(measureJwt(await sign(ecKey, 'ES256', 'ec-1')).signatureBytes).toBe(64);
    expect(measureJwt(await sign(pqKey, 'ML-DSA-65', 'pq-1')).signatureBytes).toBe(3309);
  });

  it('flags ML-DSA-65 ID tokens with realistic claims as too big for a cookie', async () => {
    const claims = { email: 'alice.nakamura@example.com', email_verified: true, given_name: 'Alice' };
    const classical = measureJwt(await sign(ecKey, 'ES256', 'ec-1', claims));
    const pq = measureJwt(await sign(pqKey, 'ML-DSA-65', 'pq-1', claims));
    expect(classical.fitsInCookie).toBe(true);
    expect(pq.fitsInCookie).toBe(false);
    expect(pq.totalBytes).toBeGreaterThan(4096);
  });

  it('refuses input that is not a compact JWT', () => {
    expect(() => measureJwt('not-a-token')).toThrow(TypeError);
  });
});
