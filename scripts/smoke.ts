/**
 * `npm run smoke`: signs in to both demo apps through a real deployment
 * (for example the kind cluster in CI, reached through port-forwards) and
 * checks each app received the ID token algorithm it should.
 *
 *   ISSUER=http://localhost:3000 LEGACY_URL=http://localhost:3001 PQ_URL=http://localhost:3002 npm run smoke
 */
import { TestBrowser } from '../tests/support/browser.ts';

const issuer = process.env.ISSUER ?? 'http://localhost:3000';
const apps = [
  { name: 'Legacy App', url: process.env.LEGACY_URL ?? 'http://localhost:3001', alg: 'ES256' },
  { name: 'PQ-Ready App', url: process.env.PQ_URL ?? 'http://localhost:3002', alg: 'ML-DSA-65' },
];

function check(condition: boolean, message: string) {
  if (!condition) {
    console.error(`✗ ${message}`);
    process.exit(1);
  }
  console.log(`✓ ${message}`);
}

const discovery = (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
check(discovery.issuer === issuer, `discovery document served for ${issuer}`);

const jwks = (await (await fetch(`${issuer}/jwks`)).json()) as { keys: { kty: string; alg: string }[] };
check(
  jwks.keys.some((k) => k.kty === 'AKP' && k.alg === 'ML-DSA-65'),
  'JWKS publishes an ML-DSA-65 (AKP) key',
);

for (const app of apps) {
  const browser = new TestBrowser();
  const loginPage = await browser.navigate(`${app.url}/login`);
  check(loginPage.body.includes('Sign in'), `${app.name}: redirected to the provider's login page`);
  const home = await browser.submitLogin(loginPage, 'alice', 'quantum-safe');
  check(home.body.includes('Hi, Alice'), `${app.name}: signed in as Alice`);
  check(home.body.includes(`<b>${app.alg}</b>`), `${app.name}: ID token signed with ${app.alg}`);
}
console.log('\nSmoke test passed.');
