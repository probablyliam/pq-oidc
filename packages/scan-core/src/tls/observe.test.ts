import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PinnedTarget } from '../net/resolve.ts';
import { labProfile, startLabServer } from '../testing/lab.ts';
import type { LabServer } from '../testing/lab.ts';
import type { HandshakeObservation } from './handshake.ts';
import { generateKeyShare } from './keyshare.ts';
import { observeHandshake } from './observe.ts';
import type { ProbeSpec } from './observe.ts';
import { GROUP, SIGNATURE_SCHEMES_CLASSICAL, SIGNATURE_SCHEMES_WITH_PQ } from './registry.ts';

/**
 * The observer against real OpenSSL servers (Node's TLS stack), which is an
 * independent implementation of everything the observer implements itself.
 */
const servers = new Map<string, LabServer>();
beforeAll(async () => {
  for (const id of ['classical', 'hybrid', 'hybrid-only', 'pq', 'tls12', 'rsa-kex', 'expired']) {
    servers.set(id, await startLabServer(labProfile(id)));
  }
});
afterAll(() => Promise.all([...servers.values()].map((s) => s.close())));

const pinned = (id: string): PinnedTarget => ({
  hostname: 'localhost',
  port: servers.get(id)!.port,
  address: '127.0.0.1',
  family: 4,
  resolved: [],
  isLab: true,
  hasHostname: true,
});

const withShares = (groups: number[], shares: number[], extra: Partial<ProbeSpec> = {}): ProbeSpec => ({
  versions: ['1.3', '1.2'],
  groups,
  keyShares: shares.map(generateKeyShare),
  signatureSchemes: SIGNATURE_SCHEMES_WITH_PQ,
  alpn: ['http/1.1'],
  ...extra,
});

const modern = () => withShares([GROUP.X25519MLKEM768, GROUP.x25519, GROUP.secp256r1], [GROUP.X25519MLKEM768, GROUP.x25519]);
const classicalOnly = () => withShares([GROUP.x25519, GROUP.secp256r1], [GROUP.x25519], { signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL });
const tls12Only = () => withShares([GROUP.x25519, GROUP.secp256r1], [], { versions: ['1.2'], signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL });
/** Offers one group and no key share: a server that supports the group must ask for a share (HelloRetryRequest). */
const askAbout = (group: number) => withShares([group], [], { versions: ['1.3'] });

const leafKey = (seen: HandshakeObservation) => new crypto.X509Certificate(seen.certificates![0]!).publicKey;

describe('TLS 1.3 handshakes', () => {
  it('completes a classical X25519 handshake and verifies the ECDSA CertificateVerify', async () => {
    const seen = await observeHandshake(pinned('classical'), modern());
    expect(seen).toMatchObject({
      outcome: 'handshake',
      version: 0x0304,
      group: GROUP.x25519,
      signatureScheme: 0x0403, // ecdsa_secp256r1_sha256
      signatureValid: true,
      finishedValid: true,
      alpn: 'http/1.1',
    });
    expect(seen.certificates).toHaveLength(2);
    expect(seen.certificates![0]!.equals(servers.get('classical')!.chain[0]!.der)).toBe(true);
    expect(leafKey(seen).asymmetricKeyDetails).toMatchObject({ namedCurve: 'prime256v1' });
  });

  it('completes a hybrid X25519MLKEM768 handshake', async () => {
    const seen = await observeHandshake(pinned('hybrid'), modern());
    expect(seen).toMatchObject({ outcome: 'handshake', version: 0x0304, group: GROUP.X25519MLKEM768, signatureValid: true, finishedValid: true });
  });

  it.each([
    ['SecP256r1MLKEM768', 'hybrid-only', GROUP.SecP256r1MLKEM768],
    ['SecP384r1MLKEM1024', 'pq', GROUP.SecP384r1MLKEM1024],
    ['MLKEM768', 'pq', GROUP.MLKEM768],
    ['MLKEM1024', 'pq', GROUP.MLKEM1024],
    ['secp256r1', 'classical', GROUP.secp256r1],
    ['secp384r1', 'classical', GROUP.secp384r1],
  ])('completes a handshake in %s', async (_name, server, group) => {
    // Finished only verifies if this side derived the same secret as OpenSSL did for that group.
    const seen = await observeHandshake(pinned(server), withShares([group], [group], { versions: ['1.3'] }));
    expect(seen).toMatchObject({ outcome: 'handshake', group, finishedValid: true, signatureValid: true });
  });

  it('reads an ML-DSA-65 certificate chain and verifies an ML-DSA CertificateVerify', async () => {
    const seen = await observeHandshake(pinned('pq'), modern());
    expect(seen).toMatchObject({ outcome: 'handshake', group: GROUP.X25519MLKEM768, signatureScheme: 0x0905, signatureValid: true, finishedValid: true });
    expect(leafKey(seen).asymmetricKeyType).toBe('ml-dsa-65');
    expect(new crypto.X509Certificate(seen.certificates![0]!).signatureAlgorithm).toBe('ML-DSA-65');
  });

  it('gets no certificate from an ML-DSA-only server when it does not offer ML-DSA', async () => {
    const seen = await observeHandshake(pinned('pq'), withShares([GROUP.X25519MLKEM768], [GROUP.X25519MLKEM768], { signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL }));
    expect(seen).toMatchObject({ outcome: 'alert', alert: { name: 'handshake_failure' } });
  });
});

describe('what a client without post-quantum support gets', () => {
  it('still connects to a server that keeps classical groups', async () => {
    const seen = await observeHandshake(pinned('hybrid'), classicalOnly());
    expect(seen).toMatchObject({ outcome: 'handshake', version: 0x0304, group: GROUP.x25519 });
  });

  it('is refused by a server that requires hybrid key exchange', async () => {
    const seen = await observeHandshake(pinned('hybrid-only'), classicalOnly());
    expect(seen).toMatchObject({ outcome: 'alert', alert: { level: 2, name: 'handshake_failure' } });
    expect(seen.group).toBeUndefined();
  });
});

describe('asking which groups a server supports', () => {
  it.each([
    ['hybrid', GROUP.X25519MLKEM768, true],
    ['hybrid', GROUP.SecP256r1MLKEM768, false],
    ['hybrid', GROUP.MLKEM768, false],
    ['hybrid-only', GROUP.SecP256r1MLKEM768, true],
    ['pq', GROUP.MLKEM1024, true],
    ['pq', GROUP.SecP384r1MLKEM1024, true],
    ['classical', GROUP.X25519MLKEM768, false],
    ['classical', GROUP.secp384r1, true],
  ])('%s server, group 0x%s: supported = %s', async (server, group, supported) => {
    const seen = await observeHandshake(pinned(server), askAbout(group));
    if (supported) expect(seen).toMatchObject({ outcome: 'hello-retry-request', group });
    else expect(seen).toMatchObject({ outcome: 'alert', alert: { name: 'handshake_failure' } });
  });
});

describe('TLS 1.2', () => {
  it('reads the ECDHE curve, the certificate and a valid ServerKeyExchange signature', async () => {
    const seen = await observeHandshake(pinned('tls12'), modern());
    expect(seen).toMatchObject({ outcome: 'handshake', version: 0x0303, group: GROUP.secp256r1, signatureValid: true });
    expect(seen.finishedValid).toBeUndefined();
    expect(leafKey(seen).asymmetricKeyType).toBe('rsa');
    expect(seen.certificates).toHaveLength(2);
  });

  it('sees RSA key transport: no key-exchange group and no signature', async () => {
    const seen = await observeHandshake(pinned('rsa-kex'), tls12Only());
    expect(seen).toMatchObject({ outcome: 'handshake', version: 0x0303, cipherSuite: 0x009d });
    expect(seen.group).toBeUndefined();
    expect(seen.signatureScheme).toBeUndefined();
  });

  it('negotiates TLS 1.2 with a TLS 1.3 server when only 1.2 is offered', async () => {
    const seen = await observeHandshake(pinned('classical'), tls12Only());
    expect(seen).toMatchObject({ outcome: 'handshake', version: 0x0303, group: GROUP.x25519, signatureValid: true });
  });

  it('is refused by a server whose minimum is TLS 1.3', async () => {
    const seen = await observeHandshake(pinned('pq'), tls12Only());
    expect(seen).toMatchObject({ outcome: 'alert', alert: { name: 'protocol_version' } });
  });
});

describe('servers that do not cooperate', () => {
  it('still reads an expired self-signed certificate (trust is judged elsewhere)', async () => {
    const seen = await observeHandshake(pinned('expired'), modern());
    expect(seen).toMatchObject({ outcome: 'handshake', signatureValid: true });
    expect(new Date(new crypto.X509Certificate(seen.certificates![0]!).validTo).getTime()).toBeLessThan(Date.now());
  });

  it('reports a closed port as unreachable', async () => {
    const closed = await startLabServer(labProfile('classical'));
    await closed.close();
    const seen = await observeHandshake({ ...pinned('classical'), port: closed.port }, modern(), { connectTimeoutMs: 1000 });
    expect(seen.outcome).toBe('unreachable');
  });
});
