import { describe, expect, it } from 'vitest';
import trace from './fixtures/rfc8448-simple-1rtt.json' with { type: 'json' };
import { applicationSecrets, certificateVerifyInput, finishedVerifyData, handshakeSecrets, hkdfExpandLabel, recordNonce, trafficKeys, transcriptHash } from './keyschedule.ts';
import { x25519KeyShareFromPrivate } from './keyshare.ts';

const bytes = (hex: string) => Buffer.from(hex, 'hex');
const hex = (value: Uint8Array) => Buffer.from(value).toString('hex');

/**
 * RFC 8448 publishes every intermediate value of a real TLS 1.3 handshake.
 * If the key schedule here reproduces them, it is the key schedule.
 */
describe('TLS 1.3 key schedule against the RFC 8448 trace', () => {
  const clientHello = bytes(trace.clientHello);
  const serverHello = bytes(trace.serverHello);
  // In the trace's ServerHello the X25519 share is followed only by the 6-byte supported_versions extension.
  const serverShare = serverHello.subarray(serverHello.length - 38, serverHello.length - 6);
  const sharedSecret = x25519KeyShareFromPrivate(bytes(trace.clientX25519Private)).sharedSecret(serverShare);
  const helloHash = transcriptHash('sha256', clientHello, serverHello);
  const handshake = handshakeSecrets('sha256', sharedSecret, helloHash);

  it('hashes ClientHello..ServerHello to the published value', () => {
    expect(hex(helloHash)).toBe(trace.expected.helloHash);
  });

  it('derives the handshake secret and both handshake traffic secrets', () => {
    expect(hex(handshake.handshakeSecret)).toBe(trace.expected.handshakeSecret);
    expect(hex(handshake.clientHandshakeTraffic)).toBe(trace.expected.clientHandshakeTraffic);
    expect(hex(handshake.serverHandshakeTraffic)).toBe(trace.expected.serverHandshakeTraffic);
  });

  it('derives the server handshake key and IV', () => {
    const keys = trafficKeys('sha256', handshake.serverHandshakeTraffic, 16);
    expect(hex(keys.key)).toBe(trace.expected.serverHandshakeKey);
    expect(hex(keys.iv)).toBe(trace.expected.serverHandshakeIv);
  });

  it('computes the server Finished value', () => {
    const upToCertificateVerify = transcriptHash(
      'sha256',
      clientHello,
      serverHello,
      bytes(trace.expected.encryptedExtensions),
      bytes(trace.expected.certificate),
      bytes(trace.expected.certificateVerify),
    );
    expect(hex(finishedVerifyData('sha256', handshake.serverHandshakeTraffic, upToCertificateVerify))).toBe(trace.expected.serverFinishedVerifyData);
  });

  it('derives the master secret and both application traffic secrets', () => {
    const upToFinished = transcriptHash('sha256', clientHello, serverHello, bytes(trace.serverFlightPlaintext));
    const application = applicationSecrets('sha256', handshake.handshakeSecret, upToFinished);
    expect(hex(application.masterSecret)).toBe(trace.expected.masterSecret);
    expect(hex(application.clientApplicationTraffic)).toBe(trace.expected.clientApplicationTraffic);
    expect(hex(application.serverApplicationTraffic)).toBe(trace.expected.serverApplicationTraffic);
  });
});

describe('building blocks', () => {
  it('encodes the HKDF label structure from RFC 8446 §7.1', () => {
    // Derive-Secret(early secret, "derived", "") for SHA-256 is a published constant.
    const early = bytes('33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a');
    expect(hex(hkdfExpandLabel('sha256', early, 'derived', transcriptHash('sha256'), 32))).toBe('6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba');
  });

  it('XORs the record sequence number into the end of the IV', () => {
    const iv = bytes('5d313eb2671276ee13000b30');
    expect(hex(recordNonce(iv, 0))).toBe('5d313eb2671276ee13000b30');
    expect(hex(recordNonce(iv, 1))).toBe('5d313eb2671276ee13000b31');
    expect(hex(recordNonce(iv, 0x0102))).toBe('5d313eb2671276ee13000a32');
    expect(hex(iv)).toBe('5d313eb2671276ee13000b30'); // input untouched
  });

  it('frames the CertificateVerify input with 64 spaces, the context string and a zero byte', () => {
    const input = Buffer.from(certificateVerifyInput(bytes('aabb')));
    expect(input.subarray(0, 64).every((b) => b === 0x20)).toBe(true);
    expect(input.subarray(64, 97).toString()).toBe('TLS 1.3, server CertificateVerify');
    expect(hex(input.subarray(97))).toBe('00aabb');
  });
});
