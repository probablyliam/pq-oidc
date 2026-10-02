import { constants, createHmac, KeyObject, sign as rawSign } from 'node:crypto';
import { CompactEncrypt, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { analyzeToken, describeSignature } from './analyze.ts';
import { jsonToBase64url } from './base64url.ts';
import { describeJweAlg, describeJwsAlg } from './jose.ts';
import { checkSignature } from './signature.ts';
import type { Jwk } from './signature.ts';

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;
const ALGS = ['RS256', 'PS256', 'ES256', 'ES384', 'EdDSA', 'ML-DSA-65'] as const;
const pairs = {} as Record<(typeof ALGS)[number], KeyPair>;
const jwks: { keys: Jwk[] } = { keys: [] };
const NOW = 1_800_000_000;

beforeAll(async () => {
  for (const alg of ALGS) {
    pairs[alg] = await generateKeyPair(alg, { extractable: true });
    jwks.keys.push({ ...(await exportJWK(pairs[alg].publicKey)), kid: `key-${alg}`, alg: alg === 'EdDSA' ? undefined : alg, use: 'sig' });
  }
});

const claims = { iss: 'https://issuer.example', sub: 'alice', aud: 'payroll', iat: NOW - 60, exp: NOW + 3540 };
const sign = (alg: (typeof ALGS)[number], header: Record<string, unknown> = {}, payload: Record<string, unknown> = claims) =>
  new SignJWT(payload).setProtectedHeader({ alg, kid: `key-${alg}`, typ: 'JWT', ...header }).sign(pairs[alg].privateKey);
const unsigned = (header: Record<string, unknown>, payload: Record<string, unknown> = claims, signature = '') => `${jsonToBase64url(header)}.${jsonToBase64url(payload)}.${signature}`;
const finding = (token: string, id: string) => analyzeToken(token, NOW).findings.find((f) => f.id === id);

describe('verifying a signature against published keys', () => {
  it.each(ALGS)('accepts a genuine %s token', async (alg) => {
    const check = await checkSignature(await sign(alg), jwks);
    expect(check.status).toBe('valid');
  });

  it('reports which key verified it', async () => {
    const check = await checkSignature(await sign('ML-DSA-65'), jwks);
    expect(check).toMatchObject({ status: 'valid', key: { kid: 'key-ML-DSA-65', strength: 'ML-DSA-65', quantumSafe: true } });
  });

  it('rejects a token whose payload was edited', async () => {
    const [header, , signature] = (await sign('ES256')).split('.');
    const forged = `${header}.${jsonToBase64url({ ...claims, sub: 'admin' })}.${signature}`;
    expect(await checkSignature(forged, jwks)).toMatchObject({ status: 'invalid', triedKeys: 1 });
  });

  it('rejects a token signed by someone else’s key with the same key ID', async () => {
    const mallory = await generateKeyPair('ES256');
    const token = await new SignJWT(claims).setProtectedHeader({ alg: 'ES256', kid: 'key-ES256' }).sign(mallory.privateKey);
    expect((await checkSignature(token, jwks)).status).toBe('invalid');
  });

  it('tries every fitting key when the token names none', async () => {
    const token = await new SignJWT(claims).setProtectedHeader({ alg: 'ES256' }).sign(pairs.ES256.privateKey);
    expect((await checkSignature(token, jwks)).status).toBe('valid');
  });

  it('does not fall back to other keys when the named key is absent', async () => {
    const check = await checkSignature(await sign('ES256', { kid: 'rotated-away' }), jwks);
    expect(check).toMatchObject({ status: 'not-verifiable', reason: 'no-matching-key' });
  });
});

describe('alg none', () => {
  it.each(['none', 'None', 'NONE', 'nOnE'])('reports alg "%s" as unsigned, never valid', async (alg) => {
    const token = unsigned({ alg, typ: 'JWT' }, { ...claims, sub: 'admin' });
    expect(await checkSignature(token, jwks)).toMatchObject({ status: 'unsigned' });
    expect(finding(token, 'signature.algorithm')).toMatchObject({ tone: 'bad', title: 'This token is not signed' });
    expect(describeSignature(analyzeToken(token, NOW), await checkSignature(token, jwks))).toMatchObject({ tone: 'bad', title: 'There is no signature to check' });
  });

  it('is not fooled by bytes left in the signature position', async () => {
    const real = (await sign('RS256')).split('.')[2]!;
    const token = unsigned({ alg: 'none' }, claims, real);
    expect((await checkSignature(token, jwks)).status).toBe('unsigned');
    expect(finding(token, 'signature.algorithm')?.detail).toMatch(/still carries bytes/);
  });
});

describe('algorithm confusion', () => {
  it('never checks an HMAC token against published keys, even one "signed" with the public key as the secret', async () => {
    // The classic attack: take the issuer's RSA public key, use its bytes as an HS256 secret.
    const rsa = jwks.keys.find((k) => k.kid === 'key-RS256')!;
    const input = `${jsonToBase64url({ alg: 'HS256', kid: 'key-RS256', typ: 'JWT' })}.${jsonToBase64url({ ...claims, sub: 'admin' })}`;
    for (const secret of [JSON.stringify(rsa), String(rsa.n), Buffer.from(String(rsa.n), 'base64url')]) {
      const token = `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
      const check = await checkSignature(token, jwks);
      expect(check).toMatchObject({ status: 'not-verifiable', reason: 'symmetric' });
    }
  });

  it('does not use a key with an algorithm it was not published for', async () => {
    // A correct PS256 signature made with the RS256 key pair: the mathematics would verify, the published key says RS256 only.
    const input = `${jsonToBase64url({ alg: 'PS256', kid: 'key-RS256' })}.${jsonToBase64url(claims)}`;
    const key = KeyObject.from(pairs.RS256.privateKey as Parameters<typeof KeyObject.from>[0]);
    const signature = rawSign('sha256', Buffer.from(input), { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
    const token = `${input}.${signature.toString('base64url')}`;
    const check = await checkSignature(token, jwks);
    expect(check).toMatchObject({ status: 'not-verifiable', reason: 'no-matching-key' });
    expect(check).toMatchObject({ detail: expect.stringContaining('not a key for PS256') });
  });

  it('does not use a key of the wrong type, whatever the key ID says', async () => {
    const token = await new SignJWT(claims).setProtectedHeader({ alg: 'ES256', kid: 'key-RS256' }).sign(pairs.ES256.privateKey);
    expect(await checkSignature(token, jwks)).toMatchObject({ status: 'not-verifiable', reason: 'no-matching-key' });
  });

  it('does not use an encryption key to check a signature', async () => {
    const encOnly = { keys: jwks.keys.filter((k) => k.kid === 'key-ES256').map((k) => ({ ...k, use: 'enc' })) };
    expect(await checkSignature(await sign('ES256'), encOnly)).toMatchObject({ status: 'not-verifiable', reason: 'no-matching-key' });
  });

  it('ignores a symmetric key that should never have been published', async () => {
    const leaked = { keys: [{ kty: 'oct', kid: 'key-RS256', k: 'c2VjcmV0' }] };
    expect(await checkSignature(await sign('RS256'), leaked)).toMatchObject({ status: 'not-verifiable', reason: 'no-matching-key' });
  });
});

describe('key material inside the token', () => {
  afterEach(() => vi.restoreAllMocks());

  it('ignores an embedded key: a token signed by its own "jwk" does not verify', async () => {
    const mallory = await generateKeyPair('ES256', { extractable: true });
    const token = await new SignJWT({ ...claims, sub: 'admin' })
      .setProtectedHeader({ alg: 'ES256', kid: 'key-ES256', jwk: await exportJWK(mallory.publicKey) })
      .sign(mallory.privateKey);
    expect((await checkSignature(token, jwks)).status).toBe('invalid');
    expect(finding(token, 'header.keys')).toMatchObject({ tone: 'caution', title: 'The header carries its own key material (jwk)' });
  });

  it('flags jku and x5u, and makes no network request for them', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const token = await sign('RS256', { jku: 'https://attacker.example/keys.json', x5u: 'http://169.254.169.254/latest/meta-data/' });
    expect(finding(token, 'header.keys')?.title).toBe('The header carries its own key material (jku, x5u)');
    expect((await checkSignature(token, jwks)).status).toBe('valid'); // verified with the published key, not the one the header points at
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('encoding, signing and encryption are told apart', () => {
  it('says a signed token is readable, not encrypted', async () => {
    const analysis = analyzeToken(await sign('RS256'), NOW);
    expect(analysis.format).toBe('jws');
    expect(analysis.payload).toMatchObject({ sub: 'alice' });
    expect(analysis.findings.find((f) => f.id === 'format.encoding')).toMatchObject({ title: 'The claims are readable by anyone who holds this token' });
    expect(analysis.findings.find((f) => f.id === 'signature.algorithm')?.detail).toMatch(/does not hide them/);
  });

  it('recognises an encrypted token and does not pretend to read it', async () => {
    const { publicKey } = await generateKeyPair('RSA-OAEP-256');
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(claims))).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' }).encrypt(publicKey);
    const analysis = analyzeToken(jwe, NOW);
    expect(analysis).toMatchObject({ format: 'jwe', jwe: { alg: 'RSA-OAEP-256', enc: 'A256GCM', quantum: 'shor' } });
    expect(analysis.payload).toBeUndefined();
    // Encryption, unlike signing, can be attacked on a stored copy.
    expect(analysis.findings.find((f) => f.id === 'quantum.encrypted')).toMatchObject({ tone: 'bad', kind: 'inference' });
    expect(await checkSignature(jwe, jwks)).toMatchObject({ status: 'not-verifiable', reason: 'malformed' });
  });

  it('says a signature break is not retroactive, and that HMAC is a different thing', async () => {
    expect(finding(await sign('ES256'), 'quantum.signature')).toMatchObject({ tone: 'caution', detail: expect.stringContaining('not retroactive') });
    expect(finding(await sign('ML-DSA-65'), 'quantum.signature')).toMatchObject({ tone: 'good' });
    const hs = unsigned({ alg: 'HS256' }, claims, 'AAAA');
    expect(finding(hs, 'signature.algorithm')?.title).toBe('Protected with HS256: a keyed hash, not a public-key signature');
    expect(finding(hs, 'quantum.signature')?.detail).toMatch(/Shor’s algorithm does not apply/);
  });
});

describe('claims', () => {
  it('reads expiry relative to now', async () => {
    expect(finding(await sign('ES256'), 'claims.time')?.title).toBe('Valid for another 59 minutes');
    expect(finding(await sign('ES256', {}, { ...claims, exp: NOW - 7200 }), 'claims.time')?.title).toBe('Expired 2 hours ago');
    expect(finding(await sign('ES256', {}, { ...claims, nbf: NOW + 600 }), 'claims.time')?.title).toBe('Not valid for another 10 minutes');
  });

  it('flags a token with no expiry or no audience', async () => {
    expect(finding(await sign('ES256', {}, { iss: 'https://issuer.example', sub: 'alice' }), 'claims.time')).toMatchObject({ tone: 'caution', title: 'The token has no expiry' });
    expect(finding(await sign('ES256', {}, { iss: 'https://issuer.example', sub: 'alice' }), 'claims.identity')?.title).toBe('It has no "aud" claim');
  });

  it('offers an issuer to fetch keys from only when it is an https URL', async () => {
    expect(analyzeToken(await sign('ES256'), NOW).issuerUrl).toBe('https://issuer.example');
    for (const iss of ['http://issuer.example', 'file:///etc/passwd', 'issuer', 42]) {
      expect(analyzeToken(await sign('ES256', {}, { ...claims, iss }), NOW).issuerUrl).toBeUndefined();
    }
  });
});

describe('things that are not JWTs', () => {
  it.each([
    ['an opaque token', 'gho_16C7e42F292c6912E7710c838347Ae178B4a'],
    ['two parts', 'abc.def'],
    ['a header that is not JSON', 'bm90IGpzb24.e30.'],
    ['a header that is a JSON array', `${Buffer.from('[1]').toString('base64url')}.e30.`],
    ['characters outside base64url', 'a+b/.c.d'],
    ['an oversized input', `${'a'.repeat(70_000)}.b.c`],
  ])('%s is reported as unreadable, not guessed at', async (_what, token) => {
    const analysis = analyzeToken(token, NOW);
    expect(analysis.format).toBe('opaque');
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ kind: 'undetermined' });
  });

  it('describes an unverified token as unverified', async () => {
    const analysis = analyzeToken(await sign('ES256'), NOW);
    expect(describeSignature(analysis, undefined)).toMatchObject({ kind: 'undetermined', title: 'The signature has not been checked' });
  });
});

describe('algorithm names', () => {
  it('classifies signature algorithms', () => {
    expect(describeJwsAlg('RS256')).toMatchObject({ kind: 'rsa-pkcs1', quantum: 'shor', publicKey: true });
    expect(describeJwsAlg('ES384')).toMatchObject({ kind: 'ecdsa', curve: 'P-384', hash: 'SHA-384' });
    expect(describeJwsAlg('ML-DSA-87')).toMatchObject({ kind: 'ml-dsa', quantum: 'no-known-attack' });
    expect(describeJwsAlg('HS512')).toMatchObject({ kind: 'hmac', publicKey: false, quantum: 'grover' });
    expect(describeJwsAlg(undefined)).toMatchObject({ kind: 'unknown' });
    expect(describeJwsAlg({ toString: () => 'none' })).toMatchObject({ kind: 'unknown' });
  });

  it('classifies JWE key management as key establishment', () => {
    expect(describeJweAlg('ECDH-ES+A256KW').quantum).toBe('shor');
    expect(describeJweAlg('RSA-OAEP').quantum).toBe('shor');
    expect(describeJweAlg('dir').quantum).toBe('grover');
    expect(describeJweAlg('A256GCMKW').quantum).toBe('grover');
  });
});
