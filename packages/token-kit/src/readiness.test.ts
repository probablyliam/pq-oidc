import { readFileSync } from 'node:fs';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { measureJwt } from './measure.ts';
import { projectToken } from './projection.ts';
import { analyzeProvider, describeKey, discoveryUrl } from './readiness.ts';

/** Real documents saved from public providers on 2026-09-30 (see fixtures/). */
function fixture(name: string) {
  const read = (file: string) => {
    const text = readFileSync(new URL(`./fixtures/${name}.${file}.json`, import.meta.url), 'utf8');
    return { json: JSON.parse(text) as Record<string, unknown>, bytes: text.length };
  };
  const jwks = read('jwks');
  return { discovery: read('discovery').json, jwks: jwks.json, jwksBytes: jwks.bytes };
}

describe('analyzeProvider on real providers', () => {
  it.each(['google', 'microsoft', 'auth0-sample'])('%s is not post-quantum ready yet', (name) => {
    const { discovery, jwks, jwksBytes } = fixture(name);
    const report = analyzeProvider(discovery, jwks, jwksBytes);
    expect(report.verdict).toBe('not-ready');
    expect(report.checks.find((c) => c.id === 'pq-algs')?.status).toBe('fail');
    expect(report.keys.length).toBeGreaterThan(0);
    expect(report.keys.every((k) => !k.quantumSafe)).toBe(true);
    expect(report.jwksBytesWithMlDsa65).toBeGreaterThan(report.jwksBytes + 2600);
  });

  it('recognises RSA key sizes', () => {
    const { discovery, jwks, jwksBytes } = fixture('google');
    const report = analyzeProvider(discovery, jwks, jwksBytes);
    expect(report.keys.every((k) => k.strength === 'RSA 2048-bit')).toBe(true);
  });
});

describe('analyzeProvider on a post-quantum provider', () => {
  const pqDiscovery = {
    issuer: 'https://pq.example',
    authorization_endpoint: 'https://pq.example/auth',
    id_token_signing_alg_values_supported: ['ES256', 'ML-DSA-65'],
    code_challenge_methods_supported: ['S256'],
    response_types_supported: ['code'],
  };

  it('reports "partial" while classical keys are still published, "ready" once they are retired', async () => {
    const ec = await exportJWK((await generateKeyPair('ES256')).publicKey);
    const pq = await exportJWK((await generateKeyPair('ML-DSA-65')).publicKey);
    const both = { keys: [{ ...ec, alg: 'ES256' }, { ...pq, alg: 'ML-DSA-65' }] };
    expect(analyzeProvider(pqDiscovery, both, 3000).verdict).toBe('partial');
    const pqOnly = { keys: [{ ...pq, alg: 'ML-DSA-65' }] };
    const report = analyzeProvider({ ...pqDiscovery, id_token_signing_alg_values_supported: ['ML-DSA-65'] }, pqOnly, 2700);
    expect(report.verdict).toBe('ready');
    expect(report.checks.every((c) => c.status === 'pass')).toBe(true);
  });

  it('flags OAuth 2.1 problems: implicit flow, missing PKCE, alg none', () => {
    const report = analyzeProvider(
      { ...pqDiscovery, response_types_supported: ['code', 'id_token token'], code_challenge_methods_supported: ['plain'], id_token_signing_alg_values_supported: ['RS256', 'none'] },
      { keys: [] },
      12,
    );
    const status = Object.fromEntries(report.checks.map((c) => [c.id, c.status]));
    expect(status).toMatchObject({ implicit: 'warn', pkce: 'warn', 'alg-none': 'fail' });
  });
});

describe('machine-identity issuers', () => {
  it('skips browser-flow checks when there is no authorization endpoint', () => {
    const report = analyzeProvider({ issuer: 'https://ci.example', id_token_signing_alg_values_supported: ['RS256'] }, { keys: [] }, 12);
    expect(report.checks.map((c) => c.id)).toEqual(['pq-algs', 'pq-keys', 'no-browser-flow']);
  });
});

describe('describeKey', () => {
  it('names ML-DSA keys by parameter set and marks them quantum-safe', async () => {
    const pq = await exportJWK((await generateKeyPair('ML-DSA-65')).publicKey);
    expect(describeKey({ ...pq, alg: 'ML-DSA-65' })).toMatchObject({ kty: 'AKP', strength: 'ML-DSA-65', quantumSafe: true });
  });
});

describe('discoveryUrl', () => {
  it('accepts issuers with or without trailing slash, or the discovery URL itself', () => {
    const expected = 'https://accounts.google.com/.well-known/openid-configuration';
    expect(discoveryUrl('https://accounts.google.com')).toBe(expected);
    expect(discoveryUrl('https://accounts.google.com/')).toBe(expected);
    expect(discoveryUrl(expected)).toBe(expected);
  });
});

describe('projectToken', () => {
  it('predicts the exact size of a token re-signed with ML-DSA', async () => {
    const claims = { sub: 'alice', name: 'Alice Nakamura', email: 'alice@example.com', groups: ['a', 'b'] };
    const ec = await generateKeyPair('ES256');
    const token = await new SignJWT(claims).setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'JWT' }).sign(ec.privateKey);

    for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const) {
      const pq = await generateKeyPair(alg);
      const real = await new SignJWT(claims).setProtectedHeader({ alg, kid: 'k1', typ: 'JWT' }).sign(pq.privateKey);
      expect(projectToken(token, alg).totalBytes).toBe(measureJwt(real).totalBytes);
    }
  });
});
