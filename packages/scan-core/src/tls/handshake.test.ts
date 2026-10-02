import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildClientHello } from './clienthello.ts';
import trace from './fixtures/rfc8448-simple-1rtt.json' with { type: 'json' };
import { HandshakeObserver } from './handshake.ts';
import { generateKeyShare, x25519KeyShareFromPrivate } from './keyshare.ts';
import { GROUP, SIGNATURE_SCHEMES_WITH_PQ } from './registry.ts';
import { CONTENT_TYPE, HANDSHAKE_TYPE, handshakeMessage, record, Writer } from './wire.ts';

const bytes = (hex: string) => Buffer.from(hex, 'hex');

function rfc8448Observer() {
  const message = bytes(trace.clientHello);
  // ClientHello: 4-byte handshake header, 2-byte legacy version, then the 32-byte random.
  return new HandshakeObserver({ message, random: message.subarray(6, 38) }, [x25519KeyShareFromPrivate(bytes(trace.clientX25519Private))]);
}

describe('replaying the RFC 8448 handshake', () => {
  it('reads version, suite and group, decrypts the flight, and verifies the signature and Finished', () => {
    const observer = rfc8448Observer();
    expect(observer.push(bytes(trace.serverHelloRecord))).toBe(false);
    expect(observer.push(bytes(trace.serverFlightRecord))).toBe(true);

    const seen = observer.observation;
    expect(seen).toMatchObject({
      outcome: 'handshake',
      version: 0x0304,
      cipherSuite: 0x1301,
      group: GROUP.x25519,
      signatureScheme: 0x0804, // rsa_pss_rsae_sha256
      signatureValid: true,
      finishedValid: true,
    });
    // The certificate inside the trace's Certificate message: 4 header + 1 context + 3 list length + 3 cert length.
    const certificate = bytes(trace.expected.certificate);
    expect(seen.certificates).toHaveLength(1);
    expect(seen.certificates![0]!.equals(certificate.subarray(11, certificate.length - 2))).toBe(true);
    expect(new crypto.X509Certificate(seen.certificates![0]!).publicKey.asymmetricKeyType).toBe('rsa');
    expect(seen.serverGroups).toEqual([0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104]);
  });

  it('gives the same answer when the bytes arrive one at a time', () => {
    const observer = rfc8448Observer();
    for (const byte of Buffer.concat([bytes(trace.serverHelloRecord), bytes(trace.serverFlightRecord)])) observer.push(Buffer.from([byte]));
    expect(observer.observation).toMatchObject({ outcome: 'handshake', signatureValid: true, finishedValid: true });
  });

  it('notices a flight that was tampered with', () => {
    const tampered = bytes(trace.serverFlightRecord);
    tampered[40]! ^= 0x01;
    const observer = rfc8448Observer();
    observer.push(bytes(trace.serverHelloRecord));
    observer.push(tampered);
    expect(observer.observation).toMatchObject({ outcome: 'malformed', version: 0x0304, group: GROUP.x25519 });
    expect(observer.observation.detail).toMatch(/did not decrypt/);
    expect(observer.observation.certificates).toBeUndefined();
  });

  it('keeps what the ServerHello showed if the connection ends before the flight', () => {
    const observer = rfc8448Observer();
    observer.push(bytes(trace.serverHelloRecord));
    observer.end('timeout');
    expect(observer.observation).toMatchObject({ outcome: 'server-hello', version: 0x0304, cipherSuite: 0x1301, group: GROUP.x25519 });
  });
});

describe('answers that are not a completed handshake', () => {
  const hello = () => {
    const share = generateKeyShare(GROUP.x25519);
    const spec = { versions: ['1.3', '1.2'] as const, groups: [GROUP.x25519], keyShares: [share], signatureSchemes: SIGNATURE_SCHEMES_WITH_PQ };
    return new HandshakeObserver(buildClientHello(spec), [share]);
  };

  it('reports a fatal alert', () => {
    const observer = hello();
    expect(observer.push(record(CONTENT_TYPE.alert, 0x0303, Buffer.from([2, 40])))).toBe(true);
    expect(observer.observation).toEqual({ outcome: 'alert', alert: { level: 2, description: 40, name: 'handshake_failure' } });
  });

  it('reads the group out of a HelloRetryRequest', () => {
    const body = new Writer()
      .u16(0x0303)
      .bytes(bytes('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c'))
      .vector(1, Buffer.alloc(32))
      .u16(0x1302)
      .u8(0)
      .vector(2, (ext) => {
        ext.u16(43).vector(2, (w) => w.u16(0x0304));
        ext.u16(51).vector(2, (w) => w.u16(GROUP.X25519MLKEM768));
      })
      .finish();
    const observer = hello();
    observer.push(record(CONTENT_TYPE.handshake, 0x0303, handshakeMessage(HANDSHAKE_TYPE.serverHello, body)));
    expect(observer.observation).toEqual({ outcome: 'hello-retry-request', version: 0x0304, cipherSuite: 0x1302, group: GROUP.X25519MLKEM768 });
  });

  it('recognises a server that is not speaking TLS', () => {
    const observer = hello();
    observer.push(Buffer.from('HTTP/1.1 400 Bad Request\r\n\r\n'));
    expect(observer.observation.outcome).toBe('not-tls');
  });

  it('reports a closed connection and a timeout as such', () => {
    const closed = hello();
    closed.end('closed', 'the server reset the connection');
    expect(closed.observation).toEqual({ outcome: 'closed', detail: 'the server reset the connection' });
    const slow = hello();
    slow.end('timeout');
    expect(slow.observation).toEqual({ outcome: 'timeout' });
  });

  it.each([
    ['a ServerHello cut short', handshakeMessage(HANDSHAKE_TYPE.serverHello, Buffer.from([3, 3, 1, 2, 3]))],
    ['a handshake message that is not a ServerHello', handshakeMessage(HANDSHAKE_TYPE.finished, Buffer.alloc(32))],
    ['a TLS 1.3 ServerHello with no key share', handshakeMessage(HANDSHAKE_TYPE.serverHello, new Writer().u16(0x0303).bytes(Buffer.alloc(32, 7)).vector(1, Buffer.alloc(0)).u16(0x1301).u8(0).vector(2, (e) => e.u16(43).vector(2, (w) => w.u16(0x0304))).finish())],
  ])('reports %s as malformed', (_what, message) => {
    const observer = hello();
    observer.push(record(CONTENT_TYPE.handshake, 0x0303, message));
    expect(observer.observation.outcome).toBe('malformed');
    expect(observer.observation.detail).toBeTruthy();
  });

  it('rejects a server key share of the wrong size instead of using it', () => {
    const body = new Writer()
      .u16(0x0303)
      .bytes(Buffer.alloc(32, 9))
      .vector(1, Buffer.alloc(0))
      .u16(0x1301)
      .u8(0)
      .vector(2, (ext) => {
        ext.u16(43).vector(2, (w) => w.u16(0x0304));
        ext.u16(51).vector(2, (w) => w.u16(GROUP.x25519).vector(2, Buffer.alloc(31, 1)));
      })
      .finish();
    const observer = hello();
    observer.push(record(CONTENT_TYPE.handshake, 0x0303, handshakeMessage(HANDSHAKE_TYPE.serverHello, body)));
    expect(observer.observation).toMatchObject({ outcome: 'malformed', detail: expect.stringContaining('requires 32') });
  });

  it('never throws, whatever bytes arrive', () => {
    // Seeded so a failure can be reproduced.
    let seed = 0x5eed;
    const next = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) & 0xff;
    for (let round = 0; round < 400; round++) {
      const observer = hello();
      const junk = Buffer.from(Array.from({ length: 5 + (next() % 200) }, next));
      // Half the rounds start with a plausible record header so the parser gets past the first check.
      if (round % 2 === 0) junk.set([20 + (next() % 4), 3, 3, 0, Math.min(junk.length, 60)]);
      expect(() => observer.push(junk)).not.toThrow();
      observer.end('closed');
      expect(observer.done).toBe(true);
    }
  });
});
