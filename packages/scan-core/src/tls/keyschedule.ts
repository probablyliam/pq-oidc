/**
 * The TLS 1.3 key schedule (RFC 8446 §7.1) without PSKs.
 *
 *            0
 *            |
 *   0 ──► HKDF-Extract = Early Secret
 *            |
 *     Derive-Secret(., "derived", "")
 *            |
 *  (EC)DHE / KEM shared secret ──► HKDF-Extract = Handshake Secret
 *            |    ├─► "c hs traffic"   protects the client's handshake messages
 *            |    └─► "s hs traffic"   protects Certificate, CertificateVerify, Finished
 *     Derive-Secret(., "derived", "")
 *            |
 *   0 ──► HKDF-Extract = Master Secret
 *                 ├─► "c ap traffic"   protects what the client sends afterwards
 *                 └─► "s ap traffic"   protects what the server sends afterwards
 *
 * The scanner uses this to decrypt a server's handshake flight; the learning
 * pages use the same functions to show a login's keys being derived. It is
 * checked against the RFC 8448 trace. Runs in Node and in browsers.
 */
import { expand, extract } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';

export type HashName = 'sha256' | 'sha384';

const HASHES = { sha256, sha384 } as const;
export const HASH_LENGTH: Record<HashName, number> = { sha256: 32, sha384: 48 };

const encoder = new TextEncoder();
const EMPTY = new Uint8Array(0);

export function transcriptHash(hash: HashName, ...messages: Uint8Array[]): Uint8Array {
  const h = HASHES[hash].create();
  for (const message of messages) h.update(message);
  return h.digest();
}

/** HKDF-Expand-Label (RFC 8446 §7.1): the label is prefixed with "tls13 " and bound to a context and length. */
export function hkdfExpandLabel(hash: HashName, secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array {
  const fullLabel = encoder.encode(`tls13 ${label}`);
  const info = new Uint8Array(2 + 1 + fullLabel.length + 1 + context.length);
  info[0] = length >> 8;
  info[1] = length & 0xff;
  info[2] = fullLabel.length;
  info.set(fullLabel, 3);
  info[3 + fullLabel.length] = context.length;
  info.set(context, 4 + fullLabel.length);
  return expand(HASHES[hash], secret, info, length);
}

/** Derive-Secret(secret, label, messages) with the transcript hash already computed. */
export function deriveSecret(hash: HashName, secret: Uint8Array, label: string, transcript: Uint8Array): Uint8Array {
  return hkdfExpandLabel(hash, secret, label, transcript, HASH_LENGTH[hash]);
}

export interface HandshakeSecrets {
  handshakeSecret: Uint8Array;
  clientHandshakeTraffic: Uint8Array;
  serverHandshakeTraffic: Uint8Array;
}

/**
 * @param sharedSecret what key establishment produced (for a hybrid group, the concatenation of both parts)
 * @param helloHash    transcript hash of ClientHello..ServerHello
 */
export function handshakeSecrets(hash: HashName, sharedSecret: Uint8Array, helloHash: Uint8Array): HandshakeSecrets {
  const zeros = new Uint8Array(HASH_LENGTH[hash]);
  const emptyHash = transcriptHash(hash);
  const earlySecret = extract(HASHES[hash], zeros, zeros);
  const handshakeSecret = extract(HASHES[hash], sharedSecret, deriveSecret(hash, earlySecret, 'derived', emptyHash));
  return {
    handshakeSecret,
    clientHandshakeTraffic: deriveSecret(hash, handshakeSecret, 'c hs traffic', helloHash),
    serverHandshakeTraffic: deriveSecret(hash, handshakeSecret, 's hs traffic', helloHash),
  };
}

export interface ApplicationSecrets {
  masterSecret: Uint8Array;
  clientApplicationTraffic: Uint8Array;
  serverApplicationTraffic: Uint8Array;
}

/** @param finishedHash transcript hash of ClientHello..server Finished */
export function applicationSecrets(hash: HashName, handshakeSecret: Uint8Array, finishedHash: Uint8Array): ApplicationSecrets {
  const zeros = new Uint8Array(HASH_LENGTH[hash]);
  const masterSecret = extract(HASHES[hash], zeros, deriveSecret(hash, handshakeSecret, 'derived', transcriptHash(hash)));
  return {
    masterSecret,
    clientApplicationTraffic: deriveSecret(hash, masterSecret, 'c ap traffic', finishedHash),
    serverApplicationTraffic: deriveSecret(hash, masterSecret, 's ap traffic', finishedHash),
  };
}

export interface TrafficKeys {
  key: Uint8Array;
  iv: Uint8Array;
}

export function trafficKeys(hash: HashName, trafficSecret: Uint8Array, keyLength: number): TrafficKeys {
  return {
    key: hkdfExpandLabel(hash, trafficSecret, 'key', EMPTY, keyLength),
    iv: hkdfExpandLabel(hash, trafficSecret, 'iv', EMPTY, 12),
  };
}

/** The value a Finished message must carry: an HMAC over the transcript, keyed from the sender's traffic secret. */
export function finishedVerifyData(hash: HashName, trafficSecret: Uint8Array, transcript: Uint8Array): Uint8Array {
  const finishedKey = hkdfExpandLabel(hash, trafficSecret, 'finished', EMPTY, HASH_LENGTH[hash]);
  return hmac(HASHES[hash], finishedKey, transcript);
}

/** Per-record nonce (RFC 8446 §5.3): the 64-bit record sequence number XORed into the end of the IV. */
export function recordNonce(iv: Uint8Array, sequence: number): Uint8Array {
  const nonce = Uint8Array.from(iv);
  let n = sequence;
  for (let i = nonce.length - 1; i >= 0 && n > 0; i--) {
    nonce[i]! ^= n & 0xff;
    n = Math.floor(n / 256);
  }
  return nonce;
}

/** The bytes a server signs in CertificateVerify (RFC 8446 §4.4.3). */
export function certificateVerifyInput(transcript: Uint8Array): Uint8Array {
  const context = encoder.encode('TLS 1.3, server CertificateVerify');
  const out = new Uint8Array(64 + context.length + 1 + transcript.length);
  out.fill(0x20, 0, 64);
  out.set(context, 64);
  out.set(transcript, 64 + context.length + 1);
  return out;
}
