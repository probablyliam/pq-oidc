import type { KeySummary } from '@pq-oidc/token-kit/readiness';
import { describe, expect, it } from 'vitest';
import { assess } from './assess.ts';
import type { Observations } from './assess.ts';
import type { CertificateSummary, OidcSummary, ProbeResult, ScanReport, SignatureFamilyName } from './report.ts';
import { plainSummary } from './summary.ts';

/**
 * Cases the lab servers cannot produce: a service whose machines hold
 * different certificates, a server that keeps a classical certificate next to
 * a post-quantum one, handshakes that time out instead of being refused, and
 * algorithms the scanner has never heard of. `assess` is pure, so each is
 * written out as what a scan would have observed.
 */
type Key = CertificateSummary['key'];
const KEY = {
  rsa: { algorithm: 'RSA 2048-bit', family: 'RSA', quantumSafe: false },
  ecdsa: { algorithm: 'ECDSA P-256', family: 'ECDSA', quantumSafe: false },
  mldsa: { algorithm: 'ML-DSA-65', family: 'ML-DSA', quantumSafe: true },
  unknown: { algorithm: 'unrecognised key type', family: 'unknown', quantumSafe: false },
} satisfies Record<string, Key>;

const signature = (algorithm: string, family: SignatureFamilyName) => ({ algorithm, oid: '', family, quantumSafe: family === 'ML-DSA' || family === 'SLH-DSA' });
const SIGNED = {
  rsa: signature('RSA PKCS#1 v1.5 with SHA-256', 'RSA'),
  ecdsa: signature('ECDSA with SHA-256', 'ECDSA'),
  mldsa: signature('ML-DSA-65', 'ML-DSA'),
  unknown: signature('1.3.9999.1', 'unknown'),
};

function certificate(position: number, key: Key, signed: CertificateSummary['signature']): CertificateSummary {
  return {
    position,
    subject: position === 0 ? 'CN=login.example' : 'CN=Example Issuing CA',
    issuer: 'CN=Example Issuing CA',
    serialNumber: '01',
    notBefore: '2026-01-01T00:00:00.000Z',
    notAfter: '2027-01-01T00:00:00.000Z',
    expired: false,
    notYetValid: false,
    selfSigned: false,
    isCa: position > 0,
    names: ['login.example'],
    key,
    signature: signed,
    fingerprint256: `${position}`.repeat(64),
    pem: '',
  };
}
const chainOf = (key: Key, signed: CertificateSummary['signature'], issuerSigned = signed) => [certificate(0, key, signed), certificate(1, key, issuerSigned)];
const PQ_CHAIN = chainOf(KEY.mldsa, SIGNED.mldsa);

const GROUP = { hybrid: 0x11ec, p384Hybrid: 0x11ed, x25519: 0x001d };
const base = (id: ProbeResult['id']): ProbeResult => ({ id, purpose: '', offered: { versions: ['1.3'], groups: [GROUP.hybrid, GROUP.x25519], keyShares: [GROUP.hybrid] }, outcome: 'handshake', durationMs: 1 });

/** A handshake that completed and received a certificate with this key. */
function got(id: ProbeResult['id'], leaf: { fingerprint: string; key: Key }, extra: Partial<ProbeResult> = {}): ProbeResult {
  return {
    ...base(id),
    version: id === 'tls12-client' ? 0x0303 : 0x0304,
    cipherSuite: id === 'tls12-client' ? 0xc02f : 0x1302,
    group: id === 'pq-capable-client' ? GROUP.hybrid : GROUP.x25519,
    signatureScheme: leaf.key.family === 'ML-DSA' ? 0x0905 : leaf.key.family === 'RSA' ? 0x0804 : 0x0403,
    signatureValid: true,
    finishedValid: id === 'tls12-client' ? undefined : true,
    leafFingerprint: leaf.fingerprint,
    leafKey: { algorithm: leaf.key.algorithm, family: leaf.key.family, quantumSafe: leaf.key.quantumSafe },
    ...extra,
  };
}
const refusedBy = (id: ProbeResult['id'], alert = 'handshake_failure'): ProbeResult => ({ ...base(id), outcome: 'alert', alert });
const silent = (id: ProbeResult['id']): ProbeResult => ({ ...base(id), outcome: 'timeout' });
/** A connection cut with no TLS answer: once, or the same way on a second attempt. */
const cut = (id: ProbeResult['id'], times: 'once' | 'twice', detail?: string): ProbeResult => ({ ...base(id), outcome: 'closed', detail, confirmed: times === 'twice' ? true : undefined });
/** Every handshake without post-quantum key exchange turned down, for a server whose certificate is post-quantum. */
const ALL_REFUSED = [refusedBy('classical-client'), refusedBy('classical-kex-client'), refusedBy('tls12-client', 'protocol_version')];

const NO_OIDC: OidcSummary = { found: false, tried: [] };
const jwk = (kty: string, strength: string, quantumSafe: boolean, alg?: string): KeySummary => ({ kid: `${strength}-1`, kty, alg, use: 'sig', strength, quantumSafe, jsonBytes: 100 });
const published = (algs: string[], keys?: KeySummary[]): OidcSummary => ({
  found: true,
  tried: [],
  discoveryUrl: 'https://login.example/.well-known/openid-configuration',
  issuer: 'https://login.example',
  issuerMatches: true,
  idTokenAlgs: algs,
  jwksUri: 'https://login.example/jwks',
  keys,
  jwksError: keys ? undefined : 'The key set could not be read (HTTP 500).',
});

/** What a scan observed: the main handshake got the chain's leaf; the others are as given. */
function observed(chain: CertificateSummary[], others: ProbeResult[], extra: Partial<Observations> = {}, main: Partial<ProbeResult> = {}): Observations {
  return {
    hostname: 'login.example',
    lab: false,
    reachable: true,
    probes: [got('pq-capable-client', { fingerprint: 'aa', key: chain[0]!.key }, main), ...others],
    groupSupport: [],
    certificates: chain,
    trust: { checked: true, trusted: true, store: 'a test store' },
    transport: { hops: [{ url: 'https://login.example/', status: 200 }], hsts: { raw: 'max-age=31536000', maxAge: 31_536_000, includeSubDomains: false, preload: false }, cookies: [] },
    oidc: NO_OIDC,
    related: [],
    ...extra,
  };
}

function assessed(seen: Observations) {
  const { layers, findings } = assess(seen);
  const report = { reachable: true, target: { url: 'https://login.example/' }, certificates: seen.certificates, tls: { probes: seen.probes, groupSupport: [] }, oidc: seen.oidc, layers, findings } as unknown as ScanReport;
  const summary = plainSummary(report);
  return {
    findings,
    finding: (id: string) => findings.find((f) => f.id === id),
    layer: (id: string) => layers.find((l) => l.id === id)!,
    answer: (id: string) => summary.answers.find((a) => a.id === id)!,
    summary,
  };
}
const sameCert = (id: ProbeResult['id'], key: Key) => got(id, { fingerprint: 'aa', key });

describe('handshakes that received different certificates', () => {
  it('of the same kind: reported as that, with no claim that the server chose by what the client offered', () => {
    const variant = assessed(observed(chainOf(KEY.rsa, SIGNED.rsa), [got('classical-client', { fingerprint: 'bb', key: KEY.rsa })])).finding('auth.variant')!;
    expect(variant.kind).toBe('observation');
    expect(variant.title).toBe('The scanner’s handshakes received different certificates');
    expect(`${variant.title} ${variant.detail}`).not.toMatch(/that do not offer ML-DSA|chooses by what the client supports|looks like/);
    expect(variant.detail).toMatch(/They carry the same kind of key \(RSA 2048-bit\)/);
    expect(variant.detail).toMatch(/this alone does not show that the server chooses/);
  });

  it('RSA for one and ECDSA for another is still not a choice by what was offered: both handshakes offered both', () => {
    const variant = assessed(observed(chainOf(KEY.rsa, SIGNED.rsa), [got('classical-client', { fingerprint: 'bb', key: KEY.ecdsa })])).finding('auth.variant')!;
    expect(variant.detail).toMatch(/Their keys are RSA 2048-bit and ECDSA P-256\. /);
    expect(variant.detail).not.toMatch(/looks like/);
  });

  it('the same certificate every time is not a finding', () => {
    expect(assessed(observed(chainOf(KEY.ecdsa, SIGNED.ecdsa), [sameCert('classical-client', KEY.ecdsa), sameCert('tls12-client', KEY.ecdsa)])).finding('auth.variant')).toBeUndefined();
  });

  it('a key type the scanner does not recognise is not called classical', () => {
    const result = assessed(observed(PQ_CHAIN, [got('classical-client', { fingerprint: 'bb', key: KEY.unknown })]));
    expect(result.layer('server-authentication').headline).toBe('Post-quantum: ML-DSA-65');
    expect(result.finding('auth.variant')!.detail).not.toMatch(/same kind of key|Their keys are/);
    expect(result.finding('auth.variant')!.evidence!.map((e) => e.value).join(' ')).toMatch(/a key type the scanner does not recognise/);
    expect(result.findings.map((f) => `${f.title} ${f.detail}`).join(' ')).not.toMatch(/classical key \(unrecognised/);
  });
});

describe('a server that keeps a classical certificate next to a post-quantum one', () => {
  const result = assessed(observed(PQ_CHAIN, [got('classical-client', { fingerprint: 'bb', key: KEY.ecdsa })]));

  it('is migrating, not finished: the classical certificate can still be forged', () => {
    expect(result.layer('server-authentication')).toMatchObject({ headline: 'Migrating: ML-DSA-65 and ECDSA P-256', exposure: 'forgery-once-quantum', tone: 'caution' });
    expect(result.finding('auth.exposure')).toMatchObject({ kind: 'inference', tone: 'caution' });
    expect(result.finding('auth.exposure')!.basedOn).toContain('auth.variant');
    expect(result.finding('auth.variant')!.detail).toMatch(/ML-DSA-65.*ECDSA P-256.*choosing by what the client offers, looks like/);
  });

  it('so the plain answer is "not today", and the verdict is not "quantum-safe"', () => {
    expect(result.answer('impersonation')).toMatchObject({ status: 'later', short: 'Not today, and it has started switching' });
    expect(result.summary.verdict).toBe('partly');
    expect(result.summary.explanation).toMatch(/started changing the way it proves who it is; the older way only matters/);
  });

  it('counts a classical certificate seen only by the TLS 1.2 handshake', () => {
    const tls12Only = assessed(observed(PQ_CHAIN, [silent('classical-client'), got('tls12-client', { fingerprint: 'bb', key: KEY.ecdsa })]));
    expect(tls12Only.layer('server-authentication')).toMatchObject({ headline: 'Migrating: ML-DSA-65 and ECDSA P-256', exposure: 'forgery-once-quantum' });
    expect(tls12Only.summary.verdict).not.toBe('safe');
  });

  it('outranks an algorithm the scanner does not recognise: a forgeable certificate was seen', () => {
    const mixed = assessed(observed(chainOf(KEY.mldsa, SIGNED.unknown, SIGNED.mldsa), [got('classical-client', { fingerprint: 'bb', key: KEY.ecdsa })]));
    expect(mixed.layer('server-authentication').exposure).toBe('forgery-once-quantum');
    expect(mixed.finding('auth.exposure')!.detail).toMatch(/has no classical part the scanner recognises, but/);
  });
});

describe('a post-quantum chain with no classical certificate seen', () => {
  it('when other clients are refused: claims only the chain the server sent, and says what clients accept is not visible', () => {
    const result = assessed(observed(PQ_CHAIN, ALL_REFUSED));
    const exposure = result.finding('auth.exposure')!;
    expect(result.layer('server-authentication').exposure).toBe('no-known-attack');
    expect(exposure.title).toBe('No known quantum attack on the certificate chain this server sent');
    expect(exposure.detail).toMatch(/a client that also accepts a classical certificate/);
    expect(result.answer('impersonation')).toMatchObject({ status: 'safe', short: 'Not by faking this certificate' });
    expect(result.answer('impersonation').answer).toMatch(/no known quantum attack can fake.*a scan cannot see what they accept/);
    expect(result.summary).toMatchObject({ verdict: 'safe', explanation: 'Everything a scan could check is quantum-safe. The site’s sign-in keys could not be checked.' });
  });

  it('is not "quantum-safe" while a client without post-quantum key exchange still connects', () => {
    const result = assessed(observed(PQ_CHAIN, [sameCert('classical-client', KEY.mldsa)]));
    expect(result.layer('key-establishment').exposure).toBe('depends-on-client');
    expect(result.summary.verdict).toBe('partly');
    expect(result.summary.explanation).toMatch(/Connections from browsers and apps that do not support it could be read later\./);
  });

  it('makes no claim about who accepts a chain that failed validation', () => {
    const result = assessed(observed(PQ_CHAIN, [refusedBy('classical-client')], { trust: { checked: true, trusted: false, error: 'the certificate has expired', store: 'a test store' } }));
    expect(result.finding('auth.exposure')!.detail).not.toMatch(/given its root|accept it/);
    expect(result.finding('auth.trust')).toMatchObject({ tone: 'bad' });
  });
});

describe('an algorithm the scanner does not recognise', () => {
  it('is not called classical, and nothing is said about a quantum computer breaking it', () => {
    const result = assessed(observed(chainOf(KEY.mldsa, SIGNED.unknown, SIGNED.mldsa), [refusedBy('classical-client')]));
    expect(result.layer('server-authentication').exposure).toBe('undetermined');
    expect(result.finding('auth.exposure')).toMatchObject({ kind: 'undetermined', tone: 'neutral' });
    expect(result.finding('auth.exposure')!.detail).not.toMatch(/Shor/);
    expect(result.answer('impersonation')).toMatchObject({ status: 'unknown', short: 'Could not tell' });
    expect(result.answer('impersonation').answer).toMatch(/does not recognise/);
  });

  it('an unrecognised certificate key is treated the same way', () => {
    const result = assessed(observed(chainOf(KEY.unknown, SIGNED.mldsa), [refusedBy('classical-client')]));
    expect(result.layer('server-authentication').exposure).toBe('undetermined');
    expect(result.finding('auth.exposure')!.detail).not.toMatch(/Shor/);
  });

  it('next to a classical one: the classical part is still reported, and the unknown part is named separately', () => {
    const exposure = assessed(observed(chainOf(KEY.ecdsa, SIGNED.unknown), [sameCert('classical-client', KEY.ecdsa)])).finding('auth.exposure')!;
    expect(exposure).toMatchObject({ kind: 'inference', tone: 'caution' });
    expect(exposure.detail).toMatch(/rests on the certificate key \(ECDSA P-256\)\./);
    expect(exposure.detail).toMatch(/a chain signature \(1\.3\.9999\.1\), which the scanner does not recognise/);
  });
});

describe('a handshake that got no answer is not a refusal', () => {
  it('timed out: what other clients get is "not known", and the key exchange is not called safe for everyone', () => {
    const result = assessed(observed(PQ_CHAIN, [silent('classical-client'), silent('tls12-client')]));
    expect(result.finding('kex.classical-client')).toMatchObject({ kind: 'undetermined', title: 'What clients without post-quantum key exchange get could not be determined' });
    expect(result.finding('kex.tls12')).toMatchObject({ kind: 'undetermined', title: 'Whether TLS 1.2 is accepted could not be determined' });
    expect(result.layer('key-establishment')).toMatchObject({ exposure: 'depends-on-client', headline: 'Hybrid: X25519MLKEM768, other clients not determined' });
    expect(result.answer('recording').answer).toMatch(/What browsers and apps without it get could not be determined\./);
    expect(result.answer('recording').answer).not.toMatch(/still get the old kind/);
    expect(result.summary.verdict).toBe('partly');
    expect(result.findings.map((f) => f.title).join(' ')).not.toMatch(/are refused|is not accepted/);
  });

  it('refused with an alert: every client that connects gets post-quantum key exchange', () => {
    const result = assessed(observed(PQ_CHAIN, ALL_REFUSED));
    expect(result.finding('kex.classical-client')).toMatchObject({ kind: 'observation', title: 'TLS 1.3 clients without post-quantum key exchange are refused' });
    expect(result.finding('kex.tls12')).toMatchObject({ kind: 'observation', title: 'TLS 1.2 is not accepted' });
    expect(result.layer('key-establishment').exposure).toBe('no-known-attack');
    expect(result.answer('recording')).toMatchObject({ status: 'safe', short: 'No' });
  });
});

describe('a post-quantum certificate does not hide what the key exchange does', () => {
  it('the classical handshake is refused for its signatures, but one that keeps ML-DSA connects with classical key exchange: not "quantum-safe"', () => {
    const kexOnly = got('classical-kex-client', { fingerprint: 'aa', key: KEY.mldsa });
    const result = assessed(observed(PQ_CHAIN, [refusedBy('classical-client'), kexOnly, refusedBy('tls12-client', 'protocol_version')]));
    expect(result.finding('kex.classical-client')).toMatchObject({ kind: 'observation', title: 'A client that accepts the post-quantum certificate can still connect with classical key exchange (x25519)' });
    expect(result.layer('key-establishment')).toMatchObject({ exposure: 'depends-on-client', headline: 'Hybrid: X25519MLKEM768, with classical fallback' });
    expect(result.summary.verdict).toBe('partly');
    expect(result.findings.map((f) => f.title).join(' ')).not.toMatch(/are refused/);
  });

  it('without that handshake, a refusal of the classical one settles nothing', () => {
    const result = assessed(observed(PQ_CHAIN, [refusedBy('classical-client'), refusedBy('tls12-client', 'protocol_version')]));
    expect(result.layer('key-establishment')).toMatchObject({ exposure: 'depends-on-client', headline: 'Hybrid: X25519MLKEM768, other clients not determined' });
    expect(result.summary.verdict).toBe('partly');
  });
});

describe('a server that requires post-quantum key exchange and still holds a classical certificate', () => {
  it('is migrating: the handshake that keeps the post-quantum groups and offers only classical signatures is given the classical one', () => {
    const sigOnly = got('classical-sig-client', { fingerprint: 'bb', key: KEY.ecdsa }, { group: GROUP.hybrid });
    const result = assessed(observed(PQ_CHAIN, [...ALL_REFUSED, sigOnly]));
    expect(result.layer('key-establishment').exposure).toBe('no-known-attack');
    expect(result.layer('server-authentication')).toMatchObject({ headline: 'Migrating: ML-DSA-65 and ECDSA P-256', exposure: 'forgery-once-quantum' });
    expect(result.answer('impersonation')).toMatchObject({ status: 'later', short: 'Not today, and it has started switching' });
    expect(result.summary.verdict).toBe('partly');
  });

  it('given the same post-quantum certificate, or refused, that handshake changes nothing', () => {
    for (const sigOnly of [got('classical-sig-client', { fingerprint: 'aa', key: KEY.mldsa }, { group: GROUP.hybrid }), refusedBy('classical-sig-client')]) {
      expect(assessed(observed(PQ_CHAIN, [...ALL_REFUSED, sigOnly])).summary.verdict).toBe('safe');
    }
  });
});

describe('TLS 1.2 counts as a way in', () => {
  const classical = chainOf(KEY.ecdsa, SIGNED.ecdsa);

  it('TLS 1.3 without post-quantum key exchange refused, TLS 1.2 answered: there is a classical fallback', () => {
    const result = assessed(observed(classical, [refusedBy('classical-client'), sameCert('tls12-client', KEY.ecdsa)]));
    expect(result.finding('kex.classical-client')!.title).toBe('TLS 1.3 clients without post-quantum key exchange are refused');
    expect(result.layer('key-establishment')).toMatchObject({ exposure: 'depends-on-client', headline: 'Hybrid: X25519MLKEM768, with classical fallback' });
    expect(result.summary.verdict).toBe('partly');
  });

  it('the classical TLS 1.3 handshake timed out, TLS 1.2 answered: still a classical fallback', () => {
    const result = assessed(observed(classical, [silent('classical-client'), sameCert('tls12-client', KEY.ecdsa)]));
    expect(result.layer('key-establishment').headline).toBe('Hybrid: X25519MLKEM768, with classical fallback');
  });
});

describe('a connection that was cut is not a refusal', () => {
  const classical = chainOf(KEY.ecdsa, SIGNED.ecdsa);

  it('cut once, by a reset or a plain close: something in between may have done it, so nothing is concluded', () => {
    for (const detail of ['the server reset the connection', undefined]) {
      const once = assessed(observed(classical, [cut('classical-client', 'once', detail), cut('tls12-client', 'once', detail)]));
      expect(once.layer('key-establishment').exposure).toBe('depends-on-client');
    }
    const result = assessed(observed(classical, [cut('classical-client', 'once', 'the server reset the connection'), cut('tls12-client', 'once', 'the server reset the connection')]));
    expect(result.layer('key-establishment')).toMatchObject({ exposure: 'depends-on-client', headline: 'Hybrid: X25519MLKEM768, other clients not determined' });
    expect(result.findings.map((f) => f.title).join(' ')).not.toMatch(/are refused|is not accepted/);
  });

  it('cut the same way twice with no alert is how some servers refuse', () => {
    const result = assessed(observed(classical, [cut('classical-client', 'twice', 'the server reset the connection'), cut('tls12-client', 'twice')]));
    expect(result.finding('kex.classical-client')!.evidence!.map((e) => e.value).join(' ')).toMatch(/the server reset the connection, on two attempts/);
    expect(result.layer('key-establishment').exposure).toBe('no-known-attack');
    expect(result.finding('kex.tls12')!.title).toBe('TLS 1.2 is not accepted');
  });
});

describe('a certificate the scanner cannot place, and a classical one for other clients', () => {
  it('is reported as classical for some clients, not as migrating', () => {
    const result = assessed(observed(chainOf(KEY.unknown, SIGNED.mldsa), [got('classical-client', { fingerprint: 'bb', key: KEY.ecdsa })]));
    expect(result.layer('server-authentication')).toMatchObject({ headline: 'Classical: ECDSA P-256 certificate, for some clients', exposure: 'forgery-once-quantum' });
    expect(result.answer('impersonation')).toMatchObject({ status: 'later', short: 'Not today' });
    expect(result.finding('auth.variant')!.detail).not.toMatch(/same kind of key/);
  });
});

describe('what is said about browsers rests on the group browsers use', () => {
  it('a hybrid group browsers do not offer: no claim that an up-to-date browser gets it', () => {
    const result = assessed(observed(chainOf(KEY.ecdsa, SIGNED.ecdsa), [sameCert('classical-client', KEY.ecdsa)], {}, { group: GROUP.p384Hybrid }));
    expect(result.layer('key-establishment').headline).toBe('Hybrid: SecP384r1MLKEM1024, with classical fallback');
    expect(result.answer('recording').short).toBe('No, if your browser or app supports it');
    expect(`${result.answer('recording').answer} ${result.summary.explanation}`).not.toMatch(/current versions of the major browsers do|as current browsers do|up-to-date/);
    expect(result.answer('recording').answer).toMatch(/When the scanner offered the kind the major browsers use, the site chose a different one, so a browser may get the old kind\./);
  });

  it('the group browsers offer: says so', () => {
    const result = assessed(observed(chainOf(KEY.ecdsa, SIGNED.ecdsa), [sameCert('classical-client', KEY.ecdsa)]));
    expect(result.answer('recording')).toMatchObject({ short: 'No, in an up-to-date browser' });
    expect(result.answer('recording').answer).toMatch(/current versions of the major browsers do\. Older browsers and apps still get the old kind/);
  });
});

describe('token signing keys', () => {
  const everyoneRefused = ALL_REFUSED;

  it('migrating keys under a post-quantum certificate: the one-line reason agrees with the sign-in answer', () => {
    const result = assessed(observed(PQ_CHAIN, everyoneRefused, { oidc: published(['ML-DSA-65', 'RS256'], [jwk('AKP', 'ML-DSA-65', true, 'ML-DSA-65'), jwk('RSA', 'RSA 2048-bit', false, 'RS256')]) }));
    expect(result.answer('sign-in').short).toBe('Not today, and it has started switching');
    expect(result.summary).toMatchObject({ verdict: 'partly' });
    expect(result.summary.explanation).toMatch(/started changing the way it vouches for sign-ins/);
    expect(result.summary.explanation).not.toMatch(/has not changed yet/);
  });

  it('metadata published but keys unreadable: says the keys could not be read, not that nothing is published', () => {
    const result = assessed(observed(PQ_CHAIN, everyoneRefused, { oidc: published([]) }));
    expect(result.answer('sign-in')).toMatchObject({ status: 'unknown', short: 'Could not read its keys' });
    expect(`${result.answer('sign-in').answer} ${result.summary.explanation}`).not.toMatch(/publishes nothing|keeps its sign-in to itself/);
  });

  it('keys unreadable, but the metadata lists only classical algorithms: that is enough to say "not today", and not "quantum-safe"', () => {
    for (const oidc of [published(['RS256', 'ES256']), published(['RS256', 'ES256'], [])]) {
      const result = assessed(observed(PQ_CHAIN, everyoneRefused, { oidc }));
      expect(result.layer('token-signing')).toMatchObject({ exposure: 'forgery-once-quantum', headline: 'Classical: RS256 and ES256' });
      expect(result.finding('token.exposure')).toMatchObject({ kind: 'inference', basedOn: ['token.metadata'] });
      expect(result.finding('token.exposure')!.detail).toMatch(/rests on the metadata alone/);
      expect(result.answer('sign-in')).toMatchObject({ status: 'later', short: 'Not today' });
      expect(result.summary.verdict).toBe('partly');
    }
  });

  it('"none" next to a classical algorithm does not hide it', () => {
    const result = assessed(observed(PQ_CHAIN, everyoneRefused, { oidc: published(['RS256', 'none']) }));
    expect(result.layer('token-signing')).toMatchObject({ exposure: 'forgery-once-quantum', headline: 'Classical: RS256' });
    expect(result.summary.verdict).toBe('partly');
  });

  it('keys unreadable and the metadata lists something that is not a classical signature: nothing is inferred', () => {
    for (const algs of [['RS256', 'HS256'], ['RS256', 'ML-DSA-65'], ['XYZ-NEW'], ['none']]) {
      expect(assessed(observed(PQ_CHAIN, everyoneRefused, { oidc: published(algs) })).layer('token-signing').exposure).toBe('undetermined');
    }
  });

  it('a key type the scanner does not recognise is "could not determine", with no claim that Shor’s algorithm breaks it', () => {
    const result = assessed(observed(PQ_CHAIN, everyoneRefused, { oidc: published(['XYZ-NEW'], [jwk('AKP', 'XYZ-NEW', false, 'XYZ-NEW')]) }));
    expect(result.layer('token-signing')).toMatchObject({ exposure: 'undetermined', headline: 'Signing keys not recognised' });
    expect(result.finding('token.exposure')).toMatchObject({ kind: 'undetermined' });
    expect(result.finding('token.exposure')!.detail).not.toMatch(/Shor/);
    expect(result.answer('sign-in')).toMatchObject({ status: 'unknown', short: 'Could not tell' });
  });

  it('an unrecognised key next to a post-quantum one is not "a classical one"', () => {
    const result = assessed(observed(PQ_CHAIN, everyoneRefused, { oidc: published(['ML-DSA-65', 'XYZ-NEW'], [jwk('AKP', 'ML-DSA-65', true, 'ML-DSA-65'), jwk('AKP', 'XYZ-NEW', false, 'XYZ-NEW')]) }));
    expect(result.layer('token-signing').exposure).toBe('undetermined');
    expect(result.findings.map((f) => f.detail).join(' ')).not.toMatch(/next to a classical one/);
  });

  it('an unrecognised key next to a classical one: the classical key decides, and the other is named', () => {
    const result = assessed(observed(PQ_CHAIN, everyoneRefused, { oidc: published(['RS256', 'XYZ-NEW'], [jwk('RSA', 'RSA 2048-bit', false, 'RS256'), jwk('AKP', 'XYZ-NEW', false, 'XYZ-NEW')]) }));
    expect(result.layer('token-signing')).toMatchObject({ exposure: 'forgery-once-quantum', headline: 'Classical: RSA 2048-bit' });
    expect(result.finding('token.exposure')!.detail).toMatch(/also has XYZ-NEW, which the scanner does not recognise/);
  });
});

describe('every one of these reports', () => {
  it('ties each inference to findings that exist', () => {
    const scenes = [
      observed(PQ_CHAIN, [silent('classical-client'), got('tls12-client', { fingerprint: 'bb', key: KEY.ecdsa })]),
      observed(PQ_CHAIN, [silent('classical-client'), silent('tls12-client')]),
      observed(chainOf(KEY.unknown, SIGNED.mldsa), [got('classical-client', { fingerprint: 'bb', key: KEY.ecdsa })]),
    ];
    for (const scene of scenes) {
      const { findings } = assess(scene);
      for (const finding of findings) for (const id of finding.basedOn ?? []) expect(findings.some((f) => f.id === id)).toBe(true);
    }
  });
});
