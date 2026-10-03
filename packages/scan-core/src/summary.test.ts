import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_POLICY } from './net/policy.ts';
import type { ScanReport } from './report.ts';
import { runScan } from './scan.ts';
import { plainSummary } from './summary.ts';
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
    expect(answer('pq', 'impersonation')).toMatchObject({ status: 'safe', short: 'No', technical: 'ML-DSA-65' });
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
