/**
 * `npm run interop`: proves the RFC 9964 implementation agrees across languages.
 *
 *   Node.js (jose, native ML-DSA)  --tokens-->  Python (pyca/cryptography) verifies
 *   Python signs an ML-DSA-65 JWT  --token--->  Node.js verifies
 *
 * It also checks that the Python verifier rejects every forged token with the
 * same rejection code as the TypeScript verifier in packages/token-kit.
 *
 * Needs Python 3.10+ with interop/python/requirements.txt installed. Set PYTHON to
 * choose the interpreter; otherwise interop/python/.venv is used if present.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import type { JWK } from 'jose';
import { jsonToBase64url, measureJwt, TokenRejectedError, verifyIdToken } from '@pq-oidc/token-kit';

const ISSUER = 'https://login.example';
const AUDIENCE = 'pq-app';
const ALGS = ['ES256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;
const now = () => Math.floor(Date.now() / 1000);
const claims = { sub: 'alice', name: 'Alice Nakamura', email: 'alice.nakamura@example.com' };

type Signer = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
type Header = { alg: string; kid: string; jwk?: JWK };
const sign = (key: Signer | Uint8Array, header: Header, extra: Record<string, unknown> = {}) =>
  new SignJWT({ ...claims, ...extra })
    .setProtectedHeader({ typ: 'JWT', ...header })
    .setIssuer(ISSUER)
    .setAudience(String(extra.aud ?? AUDIENCE))
    .setIssuedAt(Number(extra.iat ?? now()))
    .setExpirationTime(Number(extra.exp ?? now() + 300))
    .sign(key);

// 1. Keys and honest tokens for every algorithm.
const keys = new Map<string, Signer>();
const jwks: { keys: JWK[] } = { keys: [] };
const tokens: Record<string, string> = {};
for (const alg of ALGS) {
  const { privateKey, publicKey } = await generateKeyPair(alg);
  keys.set(alg, privateKey);
  jwks.keys.push({ ...(await exportJWK(publicKey)), alg, kid: alg });
  tokens[alg] = await sign(privateKey, { alg, kid: alg });
}

// 2. Forged tokens, and the verdict of the TypeScript verifier on each.
const pqKey = keys.get('ML-DSA-65')!;
const honest = tokens['ML-DSA-65']!;
const [honestHeader, , honestSignature] = honest.split('.');
const mallory = await generateKeyPair('ML-DSA-65', { extractable: true });
const attacks: Record<string, string> = {
  'edit-claims': `${honestHeader}.${jsonToBase64url({ ...measureJwt(honest).payload, sub: 'admin' })}.${honestSignature}`,
  'alg-none': `${jsonToBase64url({ alg: 'none' })}.${jsonToBase64url({ ...measureJwt(honest).payload, sub: 'admin' })}.`,
  'alg-confusion': await sign(new TextEncoder().encode(JSON.stringify(jwks.keys[2])), { alg: 'HS256', kid: 'ML-DSA-65' }),
  'embedded-key': await sign(mallory.privateKey, {
    alg: 'ML-DSA-65',
    kid: 'ML-DSA-65',
    jwk: await exportJWK(mallory.publicKey),
  }),
  expired: await sign(pqKey, { alg: 'ML-DSA-65', kid: 'ML-DSA-65' }, { iat: now() - 7200, exp: now() - 3600 }),
  'wrong-audience': await sign(pqKey, { alg: 'ML-DSA-65', kid: 'ML-DSA-65' }, { aud: 'another-app' }),
};
const expectedRejections: Record<string, string> = {};
for (const [name, token] of Object.entries(attacks)) {
  try {
    await verifyIdToken(token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: AUDIENCE, algorithms: ['ML-DSA-65', 'ES256'] });
    throw new Error(`The TypeScript verifier accepted the "${name}" attack`);
  } catch (error) {
    if (!(error instanceof TokenRejectedError)) throw error;
    expectedRejections[name] = error.code;
  }
}

// 3. A private key as an RFC 9964 seed, to compare key derivation.
const seedPair = await generateKeyPair('ML-DSA-65', { extractable: true });
const seedJwk = await exportJWK(seedPair.privateKey);

// 4. Hand everything to Python.
const dir = mkdtempSync(join(tmpdir(), 'pq-oidc-interop-'));
const fixtures = join(dir, 'fixtures.json');
const out = join(dir, 'python-token.json');
writeFileSync(
  fixtures,
  JSON.stringify({ issuer: ISSUER, audience: AUDIENCE, jwks, tokens, attacks, expectedRejections, seedKey: { priv: seedJwk.priv, pub: seedJwk.pub } }),
);

const pythonDir = join(import.meta.dirname, '..', 'interop', 'python');
const venvPython = ['Scripts/python.exe', 'bin/python'].map((p) => join(pythonDir, '.venv', p)).find(existsSync);
const python = process.env.PYTHON ?? venvPython ?? 'python';
console.log(`Node ${process.version} signed ${ALGS.length} tokens and ${Object.keys(attacks).length} forgeries. Running Python (${python})…\n`);

const result = spawnSync(python, ['-m', 'pytest', '-q', '-rs'], {
  cwd: pythonDir,
  env: { ...process.env, INTEROP_FIXTURES: fixtures, INTEROP_OUT: out },
  stdio: 'inherit',
});
if (result.status !== 0) {
  rmSync(dir, { recursive: true, force: true });
  console.error('\n✗ Python verification failed (is interop/python/requirements.txt installed?)');
  process.exit(1);
}

// 5. Verify the token Python signed.
const fromPython = JSON.parse(readFileSync(out, 'utf8')) as { token: string; jwk: JWK };
rmSync(dir, { recursive: true, force: true });
const { protectedHeader } = await jwtVerify(fromPython.token, await importJWK(fromPython.jwk, 'ML-DSA-65'), {
  issuer: ISSUER,
  audience: AUDIENCE,
  algorithms: ['ML-DSA-65'],
});
console.log(`\n✓ Python verified Node's ${ALGS.join(', ')} tokens`);
console.log(`✓ Python and TypeScript rejected all ${Object.keys(attacks).length} forgeries with the same codes`);
console.log(`✓ Node verified the ${protectedHeader.alg} token Python signed`);
