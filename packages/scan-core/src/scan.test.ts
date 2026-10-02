import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FetchError, fetchPinned } from './http/fetch.ts';
import { DEFAULT_POLICY, parseTarget, TargetRejected } from './net/policy.ts';
import type { TargetPolicy } from './net/policy.ts';
import { resolveTarget } from './net/resolve.ts';
import type { Lookup } from './net/resolve.ts';
import type { Finding, ScanReport } from './report.ts';
import { runScan } from './scan.ts';
import { LAB_PROFILES, startLabServer } from './testing/lab.ts';
import type { LabServer } from './testing/lab.ts';

/**
 * Whole scans against the lab servers. Each profile is a configuration with a
 * known right answer, so these tests check the conclusions, not just the parsing.
 */
const lab = new Map<string, LabServer>();
let policy: TargetPolicy;
/** localhost is the lab; every other name "resolves" to whatever a test says. */
const dns = new Map<string, string[]>();
const lookup: Lookup = (hostname) => Promise.resolve((dns.get(hostname) ?? ['127.0.0.1']).map((address) => ({ address, family: address.includes(':') ? 6 : 4 })));

const reports = new Map<string, ScanReport>();

beforeAll(async () => {
  for (const profile of LAB_PROFILES) lab.set(profile.id, await startLabServer(profile));
  policy = { ...DEFAULT_POLICY, labOrigins: [...lab.values()].map((s) => s.origin) };
  for (const [id, server] of lab) reports.set(id, await runScan(server.origin, { policy, lookup }));
}, 60_000);
afterAll(() => Promise.all([...lab.values()].map((s) => s.close())));

const report = (id: string) => reports.get(id)!;
const finding = (id: string, findingId: string) => report(id).findings.find((f) => f.id === findingId);
const layer = (id: string, layerId: string) => report(id).layers.find((l) => l.id === layerId)!;

describe('key establishment', () => {
  it('classical server: recorded traffic is exposed', () => {
    expect(layer('classical', 'key-establishment')).toMatchObject({ headline: 'Classical: x25519', exposure: 'harvest-now-decrypt-later', tone: 'bad' });
    expect(finding('classical', 'kex.negotiated')).toMatchObject({ kind: 'observation', title: 'Key exchange: x25519, classical' });
    expect(finding('classical', 'kex.exposure')).toMatchObject({ kind: 'inference', basedOn: expect.arrayContaining(['kex.negotiated']) });
    expect(finding('classical', 'kex.groups')?.title).toBe('No post-quantum key-exchange group is accepted');
  });

  it('hybrid server with classical fallback: protection depends on the client', () => {
    expect(layer('hybrid', 'key-establishment')).toMatchObject({ headline: 'Hybrid: X25519MLKEM768, with classical fallback', exposure: 'depends-on-client' });
    expect(finding('hybrid', 'kex.negotiated')?.title).toBe('Key exchange: X25519MLKEM768, a hybrid of X25519 and ML-KEM-768');
    expect(finding('hybrid', 'kex.classical-client')?.title).toBe('Clients without post-quantum support still connect, using x25519');
    expect(finding('hybrid', 'kex.tls12')?.title).toMatch(/^TLS 1\.2 is still accepted/);
    const groups = Object.fromEntries(report('hybrid').tls.groupSupport.map((g) => [g.name, g.supported]));
    expect(groups).toEqual({ X25519MLKEM768: true, SecP256r1MLKEM768: false, SecP384r1MLKEM1024: false, MLKEM768: false, MLKEM1024: false });
  });

  it('hybrid-only server: every session that can exist is protected', () => {
    expect(layer('hybrid-only', 'key-establishment')).toMatchObject({ exposure: 'no-known-attack', tone: 'good' });
    expect(finding('hybrid-only', 'kex.classical-client')?.title).toBe('Clients without post-quantum support are refused');
    expect(finding('hybrid-only', 'kex.tls12')?.title).toBe('TLS 1.2 is not accepted');
    expect(report('hybrid-only').tls.groupSupport.filter((g) => g.supported).map((g) => g.name)).toEqual(['X25519MLKEM768', 'SecP256r1MLKEM768']);
  });

  it('TLS 1.2 server: classical, and post-quantum groups are not even askable', () => {
    expect(layer('tls12', 'key-establishment')).toMatchObject({ headline: 'Classical: secp256r1', exposure: 'harvest-now-decrypt-later' });
    expect(finding('tls12', 'kex.negotiated')?.detail).toMatch(/chose TLS 1\.2 although TLS 1\.3 was offered/);
    expect(report('tls12').tls.groupSupport.every((g) => g.supported === false && g.evidence === 'the server did not negotiate TLS 1.3')).toBe(true);
    // No extra connections were spent asking.
    expect(report('tls12').tls.probes.map((p) => p.id)).toEqual(['pq-capable-client', 'classical-client', 'tls12-client']);
  });

  it('RSA key transport: flagged as lacking forward secrecy, and possession of the key is not claimed', () => {
    expect(finding('rsa-kex', 'kex.negotiated')).toMatchObject({ tone: 'bad', title: 'Key exchange: RSA key transport, with no forward secrecy' });
    expect(finding('rsa-kex', 'auth.proof')).toMatchObject({ kind: 'undetermined' });
  });
});

describe('server authentication', () => {
  it('ECDSA certificate: forgeable once a quantum computer exists, not retroactively', () => {
    expect(layer('hybrid', 'server-authentication')).toMatchObject({ headline: 'Classical: ECDSA P-256 certificate', exposure: 'forgery-once-quantum' });
    expect(finding('hybrid', 'auth.proof')?.title).toBe('The server proved it holds that key with ecdsa_secp256r1_sha256');
    expect(finding('hybrid', 'auth.exposure')?.detail).toMatch(/cannot be used on recorded traffic/);
  });

  it('ML-DSA chain: no known quantum attack', () => {
    expect(layer('pq', 'server-authentication')).toMatchObject({ headline: 'Post-quantum: ML-DSA-65', exposure: 'no-known-attack' });
    expect(report('pq').certificates.map((c) => [c.key.algorithm, c.signature.algorithm])).toEqual([
      ['ML-DSA-65', 'ML-DSA-65'],
      ['ML-DSA-65', 'ML-DSA-65'],
    ]);
    expect(finding('pq', 'auth.proof')?.title).toContain('mldsa65');
  });

  it('reports trust separately from algorithms, and softens it for a lab target', () => {
    expect(report('hybrid').trust).toMatchObject({ checked: true, trusted: false });
    expect(finding('hybrid', 'auth.trust')).toMatchObject({ tone: 'neutral' });
    expect(finding('hybrid', 'auth.trust')?.detail).toMatch(/Expected for a lab server/);
  });

  it('expired self-signed certificate', () => {
    expect(finding('expired', 'auth.validity')).toMatchObject({ tone: 'bad' });
    expect(report('expired').certificates[0]).toMatchObject({ expired: true, selfSigned: true });
    expect(report('expired').trust.error).toMatch(/expired|self-signed/);
  });
});

describe('the other layers', () => {
  it('treats the cipher as weakened at most, never broken', () => {
    for (const id of ['classical', 'hybrid', 'pq']) {
      expect(layer(id, 'record-protection')).toMatchObject({ headline: 'AES-256-GCM', exposure: 'reduced-margin', tone: 'good' });
    }
  });

  it('reads HSTS and cookie flags', () => {
    expect(finding('classical', 'http.hsts')).toMatchObject({ tone: 'good', title: 'HSTS tells browsers to use HTTPS only, for 365 days' });
    expect(finding('classical', 'http.cookies')).toMatchObject({ tone: 'good' });
    expect(finding('tls12', 'http.hsts')).toMatchObject({ tone: 'caution', title: 'No HSTS header' });
    expect(finding('tls12', 'http.cookies')).toMatchObject({ tone: 'caution', title: 'Cookie session can be sent over plain HTTP' });
    expect(finding('tls12', 'http.exposure')).toMatchObject({ kind: 'inference' });
    // Cookie values are never kept.
    expect(JSON.stringify(report('classical'))).not.toContain('abc');
  });

  it('token signing: read from metadata when published', () => {
    expect(layer('classical', 'token-signing')).toMatchObject({ headline: 'Classical: P-256', exposure: 'forgery-once-quantum' });
    expect(layer('hybrid', 'token-signing')).toMatchObject({ headline: 'Classical: RSA 2048-bit' });
    expect(layer('pq', 'token-signing')).toMatchObject({ headline: 'Post-quantum: ML-DSA-65', exposure: 'no-known-attack' });
    expect(report('pq').oidc).toMatchObject({ found: true, issuerMatches: true, idTokenAlgs: ['ML-DSA-65'] });
  });

  it('token signing: says so when it cannot be determined', () => {
    expect(layer('hybrid-only', 'token-signing')).toMatchObject({ headline: 'Could not determine', exposure: 'undetermined' });
    expect(finding('hybrid-only', 'token.undetermined')).toMatchObject({
      kind: 'undetermined',
      title: 'Unable to determine the application-level token signing algorithm',
    });
    expect(finding('hybrid-only', 'token.undetermined')?.evidence?.map((e) => e.value)).toEqual(['HTTP 404', 'HTTP 404']);
  });

  it('always says internal dependencies are out of reach', () => {
    for (const id of reports.keys()) expect(finding(id, 'deps.internal')).toMatchObject({ kind: 'undetermined' });
  });
});

describe('every report', () => {
  it('labels each finding, gives observations evidence and ties inferences to findings that exist', () => {
    for (const [id, scan] of reports) {
      const ids = new Set(scan.findings.map((f) => f.id));
      expect(ids.size, `${id}: finding ids are unique`).toBe(scan.findings.length);
      for (const f of scan.findings as Finding[]) {
        expect(['observation', 'inference', 'undetermined']).toContain(f.kind);
        if (f.kind === 'inference') {
          expect(f.basedOn?.length, `${id}/${f.id} names what it rests on`).toBeGreaterThan(0);
          for (const basis of f.basedOn!) expect(ids.has(basis), `${id}/${f.id} rests on ${basis}`).toBe(true);
        }
        if (f.kind === 'observation' && f.id !== 'auth.trust') expect(f.evidence?.length, `${id}/${f.id} has evidence`).toBeGreaterThan(0);
      }
      expect(scan.layers.map((l) => l.id)).toEqual(['key-establishment', 'server-authentication', 'record-protection', 'transport-policy', 'token-signing', 'dependencies']);
    }
  });

  it('contains no score', () => {
    for (const scan of reports.values()) expect(JSON.stringify(scan)).not.toMatch(/"(score|grade|rating|percent)"/i);
  });
});

describe('targets that do not answer', () => {
  it('reports an unreachable server without inventing anything', async () => {
    const gone = await startLabServer(LAB_PROFILES[0]!);
    await gone.close();
    const scan = await runScan(gone.origin, { policy: { ...DEFAULT_POLICY, labOrigins: [gone.origin] }, lookup });
    expect(scan.reachable).toBe(false);
    expect(scan.findings).toHaveLength(1);
    expect(scan.findings[0]).toMatchObject({ id: 'net.unreachable', kind: 'undetermined' });
    expect(scan.layers.every((l) => l.headline === 'Could not determine')).toBe(true);
  });
});

describe('a hostile target cannot steer the scanner', () => {
  const origin = () => lab.get('classical')!.origin;
  const scan = (path: string) => runScan(`${origin()}${path}`, { policy, lookup });

  it.each([
    ['the cloud metadata service', '/redirect/metadata', 'address-not-allowed'],
    ['loopback on another port', '/redirect/loopback', 'address-not-allowed'],
    ['an internal host name', '/redirect/internal-name', 'hostname-not-allowed'],
    ['plain http', '/redirect/plain-http', 'scheme-not-allowed'],
    ['a port outside the allowlist', '/redirect/other-port', 'port-not-allowed'],
    ['an IPv4-mapped loopback address', `/redirect/to?u=${encodeURIComponent('https://[::ffff:127.0.0.1]/')}`, 'address-not-allowed'],
    ['a decimal IP address', `/redirect/to?u=${encodeURIComponent('https://2130706433/')}`, 'address-not-allowed'],
    ['a URL with credentials', `/redirect/to?u=${encodeURIComponent('https://a:b@example.com/')}`, 'credentials-in-url'],
    ['a file URL', `/redirect/to?u=${encodeURIComponent('file:///etc/passwd')}`, 'scheme-not-allowed'],
  ])('a redirect to %s is reported, not followed', async (_what, path, code) => {
    const result = await scan(path);
    expect(result.transport.blockedRedirect?.code).toBe(code);
    expect(result.transport.hops).toHaveLength(1);
    expect(result.findings.find((f) => f.id === 'http.redirects')?.title).toBe('The page redirects somewhere the scanner will not go');
  });

  it('a redirect to a public-looking name that resolves to an internal address is refused after resolution', async () => {
    dns.set('innocent.example.com', ['10.0.0.5']);
    const result = await scan(`/redirect/to?u=${encodeURIComponent('https://innocent.example.com/')}`);
    expect(result.transport.blockedRedirect).toMatchObject({ code: 'address-not-allowed' });
    expect(result.transport.blockedRedirect?.reason).toMatch(/10\.0\.0\.5.*private/);
  });

  it('a redirect loop stops at the cap', async () => {
    const server = lab.get('classical')!;
    const before = server.requests.filter((r) => r === '/redirect/loop').length;
    const result = await scan('/redirect/loop');
    expect(result.transport.blockedRedirect?.code).toBe('too-many-redirects');
    expect(server.requests.filter((r) => r === '/redirect/loop').length - before).toBe(6); // the first request and five redirects
  });

  it('an allowed same-origin redirect is followed', async () => {
    const result = await scan('/redirect/once');
    expect(result.transport.hops.map((h) => h.status)).toEqual([302, 200]);
    expect(result.transport.blockedRedirect).toBeUndefined();
  });

  it('a jwks_uri pointing at an internal address is never fetched', async () => {
    const result = await scan('/evil');
    expect(result.oidc).toMatchObject({ found: true, issuerMatches: true, jwksUri: 'https://169.254.169.254/latest/meta-data/' });
    expect(result.oidc.jwksError).toMatch(/will not fetch jwks_uri.*link-local/);
    expect(result.findings.find((f) => f.id === 'token.keys')).toMatchObject({ kind: 'undetermined' });
  });

  it('refuses an internal target outright, before any connection', async () => {
    await expect(runScan('https://169.254.169.254/', { policy, lookup })).rejects.toBeInstanceOf(TargetRejected);
    dns.set('rebind.example.com', ['192.168.1.1']);
    await expect(runScan('https://rebind.example.com/', { policy, lookup })).rejects.toMatchObject({ code: 'address-not-allowed' });
  });

  it('stops reading a response at the size cap', async () => {
    const target = parseTarget(`${origin()}/big`, policy);
    const pinned = await resolveTarget(target, { lookup });
    const started = Date.now();
    const response = await fetchPinned(target.url, pinned, { maxBytes: 100_000 });
    expect(response).toMatchObject({ status: 200, truncated: true });
    expect(response.body.length).toBe(100_000);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it('gives up on a server that never answers the request', async () => {
    const target = parseTarget(`${origin()}/slow`, policy);
    const pinned = await resolveTarget(target, { lookup });
    await expect(fetchPinned(target.url, pinned, { timeoutMs: 300 })).rejects.toBeInstanceOf(FetchError);
  });

  it('works to a deadline: a scan with no time left makes no requests', async () => {
    const server = lab.get('hybrid')!;
    const before = server.requests.length;
    const result = await runScan(server.origin, { policy, lookup, budgetMs: 0 });
    expect(server.requests.length).toBe(before);
    expect(result.findings.some((f) => f.kind === 'undetermined')).toBe(true);
  });
});
