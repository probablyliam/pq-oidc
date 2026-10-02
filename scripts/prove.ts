/**
 * `npm run prove`: evidence that the project does what it says, checked by
 * code that shares nothing with the code under test.
 *
 *  1. Starts the real provider and performs a real sign-in for each app.
 *  2. Reads the provider's published keys with plain fetch + JSON (no project code).
 *  3. Has the independent Python verifier (pyca/cryptography) check each ID token
 *     against those live keys.
 *  4. Shows the same Python verifier refusing the post-quantum token when it is
 *     configured like a legacy app.
 *  5. Runs the readiness check against the live provider and against Google, and
 *     prints the raw key types next to its verdicts so you can compare by eye.
 */
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeProvider } from '@pq-oidc/token-kit';
import { TestBrowser } from '../tests/support/browser.ts';
import { startStack } from '../tests/support/stack.ts';

const pythonDir = join(import.meta.dirname, '..', 'interop', 'python');
const venvPython = ['Scripts/python.exe', 'bin/python'].map((p) => join(pythonDir, '.venv', p)).find(existsSync);
const python = process.env.PYTHON ?? venvPython ?? 'python';

let failures = 0;
function expect(label: string, actual: string, wanted: string) {
  const ok = actual.includes(wanted);
  if (!ok) failures++;
  console.log(`   ${ok ? '✓' : '✗'} ${label}\n       ${actual.trim() || '(no output)'}`);
}

/** Runs the Python verifier without blocking this process, which is also serving the provider. */
function pythonVerify(token: string, issuer: string, audience: string, alg: string): Promise<string> {
  const args = ['pq_jwt.py', token, '--issuer', issuer, '--audience', audience, '--alg', alg];
  return new Promise((resolve) => {
    execFile(python, args, { cwd: pythonDir, encoding: 'utf8' }, (_error, stdout, stderr) => {
      resolve(stdout || stderr.trim().split(/\r?\n/).at(-1) || '');
    });
  });
}

/** A real authorization-code sign-in as alice, returning the ID token the app would receive. */
async function signIn(issuer: string, client: { clientId: string; clientSecret: string; redirectUri: string }) {
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    client_id: client.clientId,
    response_type: 'code',
    scope: 'openid profile email',
    redirect_uri: client.redirectUri,
    state: 's',
    nonce: 'n',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
  });
  const browser = new TestBrowser();
  const stopAtApp = (url: URL) => url.pathname === '/callback';
  const loginPage = await browser.navigate(`${issuer}/auth?${params}`, { stopWhen: stopAtApp });
  const back = await browser.submitLogin(loginPage, 'alice', 'quantum-safe', { stopWhen: stopAtApp });
  const response = await fetch(`${issuer}/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${client.clientId}:${client.clientSecret}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: new URL(back.url).searchParams.get('code') ?? '',
      redirect_uri: client.redirectUri,
      code_verifier: verifier,
    }),
  });
  return ((await response.json()) as { id_token: string }).id_token;
}

async function rawKeys(issuer: string) {
  const discovery = (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
  const jwksText = await (await fetch(String(discovery.jwks_uri))).text();
  const jwks = JSON.parse(jwksText) as { keys: { kty: string; alg?: string }[] };
  return { discovery, jwks, jwksText };
}

const stack = await startStack();
try {
  console.log(`\n1. Real sign-ins against the provider at ${stack.issuer}`);
  const legacyToken = await signIn(stack.issuer, stack.clients[0]!);
  const pqToken = await signIn(stack.issuer, stack.clients[1]!);
  console.log(`   legacy-app received a ${legacyToken.length}-byte ID token, pq-app a ${pqToken.length}-byte ID token`);

  console.log('\n2. The provider’s published keys, read with plain fetch (no project code)');
  const local = await rawKeys(stack.issuer);
  console.log(`   ${local.jwks.keys.map((k) => `${k.kty}/${k.alg}`).join(', ')}`);

  console.log(`\n3. Independent verification in Python (${python.includes('.venv') ? 'project venv' : python})`);
  expect('Python accepts the ES256 token', await pythonVerify(legacyToken, stack.issuer, 'legacy-app', 'ES256'), 'VALID ES256');
  expect(
    'Python accepts the ML-DSA-65 token (3,309-byte signature per FIPS 204)',
    await pythonVerify(pqToken, stack.issuer, 'pq-app', 'ML-DSA-65'),
    'VALID ML-DSA-65 sub=alice signature=3309B',
  );

  console.log('\n4. A legacy configuration refuses the post-quantum token');
  expect('Python with an ES256-only allowlist', await pythonVerify(pqToken, stack.issuer, 'pq-app', 'ES256'), 'REJECTED alg-not-allowed');
  const tampered = pqToken.slice(0, -8) + 'AAAAAAAA';
  expect('Python on a token with a corrupted signature', await pythonVerify(tampered, stack.issuer, 'pq-app', 'ML-DSA-65'), 'REJECTED bad-signature');

  console.log('\n5. Readiness verdicts next to the raw key types');
  const localReport = analyzeProvider(local.discovery, local.jwks, local.jwksText.length);
  expect(`this provider (${local.jwks.keys.map((k) => k.kty).join(' + ')} keys)`, `verdict: ${localReport.verdict}`, 'partial');
  try {
    const google = await rawKeys('https://accounts.google.com');
    const report = analyzeProvider(google.discovery, google.jwks, google.jwksText.length);
    expect(`Google (${google.jwks.keys.map((k) => `${k.kty}/${k.alg}`).join(', ')})`, `verdict: ${report.verdict}`, 'not-ready');
  } catch {
    console.log('   · skipped Google (no network)');
  }
} finally {
  await stack.close();
}

console.log(failures === 0 ? '\nAll claims held.' : `\n${failures} claim(s) did not hold.`);
process.exitCode = failures === 0 ? 0 : 1;
