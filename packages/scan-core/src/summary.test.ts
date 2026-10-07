import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_POLICY } from './net/policy.ts';
import type { ScanReport } from './report.ts';
import { runScan } from './scan.ts';
import { plainSummary } from './summary.ts';
import { issueCertificate } from './testing/certs.ts';
import { LAB_PROFILES, startLabServer } from './testing/lab.ts';
import type { LabServer } from './testing/lab.ts';

/** The plain-words summary, checked against lab servers whose right answer is known. */
const lab = new Map<string, LabServer>();
const reports = new Map<string, ScanReport>();

beforeAll(async () => {
  for (const profile of LAB_PROFILES) lab.set(profile.id, await startLabServer(profile));
  const policy = { ...DEFAULT_POLICY, labOrigins: [...lab.values()].map((s) => s.origin) };
  const lookup = () => Promise.resolve([{ address: '127.0.0.1', family: 4 as const }]);
  for (const [id, server] of lab) reports.set(id, await runScan(server.origin, { policy, lookup }));
}, 60_000);
afterAll(() => Promise.all([...lab.values()].map((s) => s.close())));

const summary = (id: string) => plainSummary(reports.get(id)!);
const answer = (id: string, which: string) => summary(id).answers.find((a) => a.id === which)!;

describe('the verdict', () => {
  it.each([
    ['classical', 'not-safe', 'Not quantum-safe'],
    ['tls12', 'not-safe', 'Not quantum-safe'],
    ['rsa-kex', 'not-safe', 'Not quantum-safe'],
    ['hybrid', 'partly', 'Partly quantum-safe'],
    ['hybrid-only', 'partly', 'Partly quantum-safe'],
    ['pq', 'safe', 'Quantum-safe'],
  ])('%s server: %s', (id, verdict, headline) => {
    expect(summary(id)).toMatchObject({ verdict, headline });
  });

  it('is "not safe" only for the risk that starts today: recordings that can be read later', () => {
    for (const id of reports.keys()) {
      const s = summary(id);
      expect(s.verdict === 'not-safe').toBe(s.answers[0]!.status === 'now');
    }
  });

  it('never says "safe" while something visible is still classical', () => {
    for (const id of reports.keys()) {
      const s = summary(id);
      if (s.verdict === 'safe') expect(s.answers.some((a) => a.status === 'later' || a.status === 'now')).toBe(false);
    }
  });

  it('a post-quantum certificate does not hide classical key exchange: a client that keeps ML-DSA and drops ML-KEM still connects', async () => {
    // The classical handshake is refused here for its signatures alone. Only one that changes the key exchange and nothing else shows the fallback.
    const server = await startLabServer({ id: 'pq-certificate', title: '', port: 0, tls: { groups: 'X25519MLKEM768:X25519', minVersion: 'TLSv1.3' }, certificate: { key: { type: 'ml-dsa-65' } }, site: {} });
    try {
      const report = await runScan(server.origin, { policy: { ...DEFAULT_POLICY, labOrigins: [server.origin] }, lookup: () => Promise.resolve([{ address: '127.0.0.1', family: 4 }]) });
      const probe = (id: string) => report.tls.probes.find((p) => p.id === id);
      expect(probe('classical-client')).toMatchObject({ outcome: 'alert' });
      expect(probe('classical-kex-client')).toMatchObject({ outcome: 'handshake', group: 0x001d, finishedValid: true });
      expect(report.layers.find((l) => l.id === 'key-establishment')).toMatchObject({ exposure: 'depends-on-client', headline: 'Hybrid: X25519MLKEM768, with classical fallback' });
      expect(plainSummary(report)).toMatchObject({ verdict: 'partly', headline: 'Partly quantum-safe' });
    } finally {
      await server.close();
    }
  });

  it('a server that requires post-quantum key exchange but still holds a classical certificate is migrating, not finished', async () => {
    // What a current browser is: hybrid key exchange, classical signatures. It is handed the classical certificate, which can be forged.
    const names = ['localhost', '127.0.0.1'];
    const postQuantum = issueCertificate({ subject: 'dual.lab.localhost', key: { type: 'ml-dsa-65' }, names });
    const classical = issueCertificate({ subject: 'dual.lab.localhost', key: { type: 'ec', curve: 'P-256' }, names });
    const server = https.createServer({ key: [postQuantum.keyPem, classical.keyPem], cert: [postQuantum.certPem, classical.certPem], ecdhCurve: 'X25519MLKEM768', minVersion: 'TLSv1.3' }, (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' }).end('<form><input name="password" type="password"></form>');
    });
    server.on('tlsClientError', () => {});
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const origin = `https://localhost:${(server.address() as AddressInfo).port}`;
    try {
      const report = await runScan(origin, { policy: { ...DEFAULT_POLICY, labOrigins: [origin] }, lookup: () => Promise.resolve([{ address: '127.0.0.1', family: 4 }]) });
      const probe = (id: string) => report.tls.probes.find((p) => p.id === id);
      expect(probe('classical-client')).toMatchObject({ outcome: 'alert' });
      expect(probe('classical-kex-client')).toMatchObject({ outcome: 'alert' });
      expect(probe('classical-sig-client')).toMatchObject({ outcome: 'handshake', group: 0x11ec, leafKey: { algorithm: 'ECDSA P-256', quantumSafe: false } });
      expect(report.layers.find((l) => l.id === 'key-establishment')).toMatchObject({ exposure: 'no-known-attack' });
      expect(report.layers.find((l) => l.id === 'server-authentication')).toMatchObject({ headline: 'Migrating: ML-DSA-65 and ECDSA P-256', exposure: 'forgery-once-quantum' });
      expect(plainSummary(report)).toMatchObject({ verdict: 'partly', headline: 'Partly quantum-safe' });
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('the extra handshakes are made only when they can tell something', () => {
    // A classical certificate: nothing to disentangle. A post-quantum one with no classical certificate behind it: asked, and refused, since the server has nothing to sign with.
    expect(reports.get('hybrid-only')!.tls.probes.map((p) => p.id)).not.toContain('classical-sig-client');
    expect(reports.get('pq')!.tls.probes.find((p) => p.id === 'classical-sig-client')).toMatchObject({ outcome: 'alert' });
    expect(summary('pq').verdict).toBe('safe');
  });

  it('the key-exchange-only handshake is made only when it can tell something: not for a classical certificate, and it confirms a real refusal', () => {
    expect(reports.get('hybrid-only')!.tls.probes.map((p) => p.id)).not.toContain('classical-kex-client');
    expect(reports.get('pq')!.tls.probes.find((p) => p.id === 'classical-kex-client')).toMatchObject({ outcome: 'alert' });
  });

  it('says so when nothing could be checked', async () => {
    const gone = await startLabServer(LAB_PROFILES[0]!);
    await gone.close();
    const report = await runScan(gone.origin, { policy: { ...DEFAULT_POLICY, labOrigins: [gone.origin] }, lookup: () => Promise.resolve([{ address: '127.0.0.1', family: 4 }]) });
    expect(plainSummary(report)).toMatchObject({ verdict: 'unknown', headline: 'Could not check', explanation: 'The scanner could not connect to this address.' });
  });
});

describe('the three answers', () => {
  it('recording: yes for classical key exchange, no for hybrid, with the algorithm named for those who want it', () => {
    expect(answer('classical', 'recording')).toMatchObject({ status: 'now', short: 'Yes', technical: 'x25519' });
    expect(answer('hybrid', 'recording')).toMatchObject({ status: 'safe', short: 'No, in an up-to-date browser', technical: 'X25519MLKEM768, with classical fallback' });
    expect(answer('hybrid-only', 'recording')).toMatchObject({ status: 'safe', short: 'No' });
  });

  it('impersonation: "not today" for a classical certificate, and it says nothing recorded is affected', () => {
    expect(answer('hybrid', 'impersonation')).toMatchObject({ status: 'later', short: 'Not today', technical: 'ECDSA P-256' });
    expect(answer('hybrid', 'impersonation').answer).toMatch(/Nothing recorded today is affected/);
    expect(answer('pq', 'impersonation')).toMatchObject({ status: 'safe', short: 'Not by faking this certificate', technical: 'ML-DSA-65' });
  });

  it('impersonation: says the fix is not in a public site’s own hands, without claiming what browsers accept this year', () => {
    expect(answer('hybrid', 'impersonation').answer).toMatch(/cannot change this alone: certificate authorities must issue quantum-safe certificates, and browsers must stop accepting the older kind/);
    for (const id of reports.keys()) expect(answer(id, 'impersonation').answer).not.toMatch(/browsers do not accept/);
  });

  it('the verdict’s one-line reason carries the same condition as the recording answer', () => {
    expect(summary('hybrid').explanation).toMatch(/when your browser or app supports the newer key exchange/);
    expect(summary('hybrid-only').explanation).toMatch(/^What you send is protected from future quantum computers\. /);
  });

  it('sign-in: read from published keys, and "cannot tell" when nothing is published', () => {
    expect(answer('hybrid', 'sign-in')).toMatchObject({ status: 'later', technical: 'RSA 2048-bit' });
    expect(answer('pq', 'sign-in')).toMatchObject({ status: 'safe' });
    expect(answer('hybrid-only', 'sign-in')).toMatchObject({ status: 'unknown', short: 'Nothing published to check', technical: '' });
  });

  it('says what kind of address each one is', () => {
    expect(summary('classical').page).toMatchObject({ kind: 'sign-in-service', note: 'A sign-in service: other sites send people here to log in. A scan can also check how it signs you in, not just the connection.' });
    expect(summary('hybrid-only').page).toMatchObject({ kind: 'sign-in-page', note: 'A sign-in page: it asks for a password.' });
  });

  it('each answer links to the part of the explanation that shows it', () => {
    expect(answer('classical', 'recording').learn).toMatchObject({ view: 'login', landmark: 'harvest', mode: 'classical' });
    expect(answer('hybrid-only', 'sign-in').learn).toMatchObject({ view: 'token' });
  });

  it('uses plain words: no algorithm names in the sentences', () => {
    for (const id of reports.keys()) {
      for (const a of summary(id).answers) expect(`${a.short} ${a.answer}`).not.toMatch(/X25519|ECDSA|RSA|ML-KEM|ML-DSA|TLS|HKDF|AES/);
    }
  });
});

describe('problems that are not about quantum computers', () => {
  it('are listed separately, and do not change the quantum verdict', () => {
    expect(summary('tls12').alsoNoticed).toEqual(expect.arrayContaining(['No HSTS header', 'Cookie session can be sent over plain HTTP']));
    expect(summary('expired').alsoNoticed.join(' ')).toMatch(/certificate expired/);
    expect(summary('classical').alsoNoticed).toEqual([]);
    // A lab certificate is untrusted by design; that is not reported as a problem.
    expect(summary('hybrid').alsoNoticed).toEqual([]);
  });
});
