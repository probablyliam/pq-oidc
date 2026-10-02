/**
 * `npm run check -- <issuer URL>`   post-quantum readiness of any OIDC provider
 * `npm run check -- <JWT>`          what happens to a token when it is re-signed with ML-DSA
 *
 * Same analysis as the Token Lab, without browser CORS limits.
 *   npm run check -- https://token.actions.githubusercontent.com
 */
import {
  ALGORITHMS,
  analyzeProvider,
  discoveryUrl,
  measureJwt,
  projectToken,
  SIZE_LIMITS,
} from '@pq-oidc/token-kit';
import type { CheckStatus, SigningAlg } from '@pq-oidc/token-kit';

const input = process.argv[2];
if (!input) {
  console.error('Usage: npm run check -- <issuer URL | JWT>');
  process.exit(2);
}

const ICON: Record<CheckStatus, string> = { pass: '✓', warn: '!', fail: '✗', info: '·' };
const fmt = (n: number) => n.toLocaleString('en-US');

if (/^https?:\/\//.test(input)) {
  await checkIssuer(input);
} else {
  checkToken(input);
}

async function checkIssuer(input: string) {
  const discoveryResponse = await fetch(discoveryUrl(input));
  if (!discoveryResponse.ok) {
    console.error(`No discovery document at ${discoveryUrl(input)} (HTTP ${discoveryResponse.status}). Is this an OpenID Connect issuer URL?`);
    process.exitCode = 1;
    return;
  }
  let discovery: Record<string, unknown>;
  try {
    discovery = (await discoveryResponse.json()) as Record<string, unknown>;
  } catch {
    console.error(`${discoveryUrl(input)} did not return a discovery document. Is this an OpenID Connect issuer URL?`);
    process.exitCode = 1;
    return;
  }
  const jwksText = await (await fetch(String(discovery.jwks_uri))).text();
  const report = analyzeProvider(discovery, JSON.parse(jwksText) as Record<string, unknown>, jwksText.length);

  const verdict = { ready: 'READY', partial: 'PARTIALLY READY', 'not-ready': 'NOT READY' }[report.verdict];
  console.log(`\n${report.issuer}\nPost-quantum ID token signatures: ${verdict}\n`);
  for (const c of report.checks) console.log(`  ${ICON[c.status]} ${c.label}\n      ${c.detail}`);
  console.log('\n  Signing keys:');
  for (const k of report.keys) {
    console.log(`    ${(k.kid ?? '(no kid)').slice(0, 24).padEnd(26)}${k.strength.padEnd(16)}${k.quantumSafe ? 'quantum-safe' : 'quantum-vulnerable'}`);
  }
  console.log(`\n  JWKS today: ${fmt(report.jwksBytes)} B · with one ML-DSA-65 key added: ~${fmt(report.jwksBytesWithMlDsa65)} B\n`);
}

function checkToken(input: string) {
  const m = measureJwt(input.trim());
  console.log(`\nToken: ${m.alg}, ${fmt(m.totalBytes)} B (claims ${fmt(m.encodedPayloadBytes)} B, signature ${fmt(m.encodedSignatureBytes)} B)\n`);
  const algs: SigningAlg[] = ['ES256', 'RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
  console.log(`  ${'Algorithm'.padEnd(11)}${'Size'.padStart(9)}  ${SIZE_LIMITS.map((l) => l.label).join(' | ')}`);
  for (const alg of algs) {
    const p = projectToken(input.trim(), alg);
    const fits = SIZE_LIMITS.map((l) => {
      const used = l.id === 'cookie' ? p.cookieBytes : p.bearerHeaderBytes;
      return used <= l.bytes ? 'fits' : 'TOO BIG';
    });
    const tag = ALGORITHMS[alg].quantumSafe ? '(PQ)' : '';
    console.log(`  ${(alg + ' ' + tag).padEnd(15)}${fmt(p.totalBytes).padStart(7)} B  ${fits.join(' | ')}`);
  }
  console.log('');
}
