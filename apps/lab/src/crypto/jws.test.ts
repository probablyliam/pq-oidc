import { createLocalJWKSet, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import type { JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { TokenRejectedError, verifyIdToken } from '@pq-oidc/token-kit';
import { base64urlToBytes } from '@pq-oidc/token-kit/base64url';
import { ATTACKS, naiveVerify } from './attacks.ts';
import type { AttackContext } from './attacks.ts';
import { projectToken } from '@pq-oidc/token-kit/projection';
import { generateKey, mlDsaKeyFromSeed, resignJwt, signJwt, verifyJwt } from './jws.ts';
import type { LabKey } from './jws.ts';

const ISSUER = 'https://login.example';
const AUDIENCE = 'pq-app';
const now = () => Math.floor(Date.now() / 1000);
const claims = () => ({ iss: ISSUER, aud: AUDIENCE, sub: 'alice', name: 'Alice', iat: now(), exp: now() + 300 });

describe('interoperability with jose (Node.js native ML-DSA)', () => {
  it.each(['ES256', 'RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const)(
    'a %s token signed in the browser verifies with jose',
    async (alg) => {
      const key = await generateKey(alg, 'k1');
      const token = await signJwt(key, claims());
      const publicKey = await importJWK(key.publicJwk as JWK, alg);
      const { protectedHeader } = await jwtVerify(token, publicKey, { issuer: ISSUER, audience: AUDIENCE });
      expect(protectedHeader.alg).toBe(alg);
    },
  );

  it('an ML-DSA-65 token signed by jose verifies in the browser, using the RFC 9964 AKP key format', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ML-DSA-65', { extractable: true });
    const token = await new SignJWT(claims()).setProtectedHeader({ alg: 'ML-DSA-65', kid: 'k1' }).sign(privateKey);
    const pub = (await exportJWK(publicKey)).pub ?? '';
    const result = await verifyJwt(token, [{ kty: 'AKP', alg: 'ML-DSA-65', kid: 'k1', pub }], {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['ML-DSA-65'],
    });
    expect(result.ok).toBe(true);
  });

  it('derives the same ML-DSA-65 public key from a private seed as Node.js does', async () => {
    const { privateKey } = await generateKeyPair('ML-DSA-65', { extractable: true });
    const jwk = await exportJWK(privateKey);
    const labKey = mlDsaKeyFromSeed('ML-DSA-65', base64urlToBytes(jwk.priv ?? ''), 'k1');
    expect(labKey.publicJwk.kty === 'AKP' && labKey.publicJwk.pub).toBe(jwk.pub);
  });
});

describe('token check', () => {
  it('re-signing a real RS256 token gives exactly the projected size, and the result verifies', async () => {
    const rsa = await generateKey('RS256', 'corp-key');
    const token = await signJwt(rsa, { ...claims(), groups: ['a', 'b', 'c'], email: 'alice@example.com' });
    for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const) {
      const key = await generateKey(alg, 'corp-key');
      const resigned = await resignJwt(key, token);
      expect(resigned.length).toBe(projectToken(token, alg).totalBytes);
      expect(resigned.split('.')[1]).toBe(token.split('.')[1]); // claims bytes untouched
      const result = await verifyJwt(resigned, [key.publicJwk], { issuer: ISSUER, audience: AUDIENCE, algorithms: [alg] });
      expect(result.ok).toBe(true);
    }
  });
});

describe('attack playground', () => {
  let providerKey: LabKey;
  let ctx: AttackContext;
  beforeAll(async () => {
    providerKey = await generateKey('ML-DSA-65', 'provider-key');
    ctx = { providerKey, issuer: ISSUER, audience: AUDIENCE, claims: claims() };
  });
  const options = { issuer: ISSUER, audience: AUDIENCE, algorithms: ['ML-DSA-65', 'ES256'] };

  it('the careful verifier accepts only the honest token', async () => {
    for (const attack of ATTACKS) {
      const result = await verifyJwt(await attack.build(ctx), [providerKey.publicJwk], options);
      expect(result.ok, attack.id).toBe(attack.id === 'honest');
    }
  });

  it('the naive verifier falls for the header-based attacks', async () => {
    const fooled: string[] = [];
    for (const attack of ATTACKS) {
      const result = await naiveVerify(await attack.build(ctx), [providerKey.publicJwk]);
      if (result.ok && attack.id !== 'honest') fooled.push(attack.id);
    }
    expect(fooled.sort()).toEqual(['alg-confusion', 'alg-none', 'embedded-key', 'expired', 'wrong-audience']);
  });

  it('the browser verifier and the server verifier (token-kit + jose) reach the same verdict on every attack', async () => {
    const jwks = createLocalJWKSet({ keys: [providerKey.publicJwk as JWK] });
    for (const attack of ATTACKS) {
      const token = await attack.build(ctx);
      const browser = await verifyJwt(token, [providerKey.publicJwk], options);
      const server = await verifyIdToken(token, jwks, options).then(
        () => ({ ok: true as const, code: undefined }),
        (error: unknown) => ({ ok: false as const, code: (error as TokenRejectedError).code }),
      );
      expect({ attack: attack.id, ok: server.ok, code: server.code }).toEqual({
        attack: attack.id,
        ok: browser.ok,
        code: browser.ok ? undefined : browser.code,
      });
    }
  });
});
