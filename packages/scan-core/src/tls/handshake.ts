/**
 * Reads a server's side of a TLS handshake and records what it shows.
 *
 * This is a measuring instrument (ADR 0006). It takes the bytes a server sent
 * in reply to one ClientHello and extracts: the version, cipher suite and
 * key-exchange group from the ServerHello; for TLS 1.3, the certificate chain
 * and CertificateVerify from the encrypted flight, which it can read because
 * it completed the key exchange; for TLS 1.2, the same from the plaintext
 * Certificate and ServerKeyExchange. It checks the server's signature and
 * Finished MAC, and never sends anything after the ClientHello.
 *
 * It does no I/O, so a recorded handshake can be replayed through it in tests.
 */
import crypto from 'node:crypto';
import type { ClientHello } from './clienthello.ts';
import { EXTENSION } from './clienthello.ts';
import type { KeyShare } from './keyshare.ts';
import { certificateVerifyInput, finishedVerifyData, handshakeSecrets, recordNonce, trafficKeys, transcriptHash } from './keyschedule.ts';
import type { HashName } from './keyschedule.ts';
import { alertName, CIPHER_SUITES, SIGNATURE_SCHEMES } from './registry.ts';
import { CONTENT_TYPE, HANDSHAKE_TYPE, HandshakeReader, Reader, RecordReader, WireError } from './wire.ts';
import type { HandshakeMessage, TlsRecord } from './wire.ts';

export type HandshakeOutcome =
  /** The server's flight was read to the end: TLS 1.3 Finished, or TLS 1.2 ServerHelloDone. */
  | 'handshake'
  /** A ServerHello was read but not what followed; `detail` says why. */
  | 'server-hello'
  /** The server asked for a key share in `group`, which shows it supports that group. */
  | 'hello-retry-request'
  | 'alert'
  /** The connection closed or reset before any TLS answer. */
  | 'closed'
  | 'timeout'
  | 'not-tls'
  /** The answer was TLS but could not be parsed or decrypted. */
  | 'malformed'
  | 'unreachable';

export interface HandshakeObservation {
  outcome: HandshakeOutcome;
  detail?: string;
  alert?: { level: number; description: number; name: string };
  /** Negotiated protocol version code point (0x0304 for TLS 1.3). */
  version?: number;
  cipherSuite?: number;
  /** Key-exchange group: from `key_share` (TLS 1.3) or ServerKeyExchange (TLS 1.2 ECDHE). */
  group?: number;
  alpn?: string;
  /** DER certificates exactly as the server sent them, leaf first. */
  certificates?: Buffer[];
  /** Scheme of the signature that proves possession of the certificate key. */
  signatureScheme?: number;
  /** That signature checked against the leaf certificate's key. Undefined if it could not be checked. */
  signatureValid?: boolean;
  /** TLS 1.3: the server's Finished MAC matched the keys this side derived. */
  finishedValid?: boolean;
  /** Groups the server listed in EncryptedExtensions, when it chose to. */
  serverGroups?: number[];
  clientCertificateRequested?: boolean;
  /** TLS 1.2 DHE: size of the server's prime. */
  dhPrimeBits?: number;
}

const HELLO_RETRY_RANDOM = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex');

const AEAD: Record<string, { algorithm: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305'; keyLength: number }> = {
  'AES-128-GCM': { algorithm: 'aes-128-gcm', keyLength: 16 },
  'AES-256-GCM': { algorithm: 'aes-256-gcm', keyLength: 32 },
  'CHACHA20-POLY1305': { algorithm: 'chacha20-poly1305', keyLength: 32 },
};

interface Protection {
  hash: HashName;
  algorithm: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305';
  key: Uint8Array;
  iv: Uint8Array;
  serverTrafficSecret: Uint8Array;
  sequence: number;
}

export class HandshakeObserver {
  readonly observation: HandshakeObservation = { outcome: 'closed' };

  private readonly clientHello: ClientHello;
  private readonly keyShares: readonly KeyShare[];
  private readonly records = new RecordReader();
  private readonly plain = new HandshakeReader();
  private readonly decrypted = new HandshakeReader();
  private readonly transcript: Buffer[];
  private state: 'hello' | 'tls12' | 'tls13' | 'done' = 'hello';
  private sawBytes = false;
  private serverRandom: Buffer = Buffer.alloc(0);
  private protection: Protection | undefined;

  constructor(clientHello: ClientHello, keyShares: readonly KeyShare[]) {
    this.clientHello = clientHello;
    this.keyShares = keyShares;
    this.transcript = [clientHello.message];
  }

  get done(): boolean {
    return this.state === 'done';
  }

  /** Feeds bytes from the server. Returns true once there is nothing more to learn from this connection. */
  push(chunk: Buffer): boolean {
    if (this.done) return true;
    try {
      this.records.push(chunk);
      for (let record = this.records.next(); record && !this.done; record = this.records.next()) {
        this.sawBytes = true;
        this.onRecord(record);
      }
    } catch (error) {
      // Bytes from an arbitrary server must never take the scanner down, whatever they trip over.
      const detail = error instanceof WireError ? error.message : `parser error: ${error instanceof Error ? error.message : String(error)}`;
      this.finish(this.sawBytes ? 'malformed' : 'not-tls', detail);
    }
    return this.done;
  }

  /** The connection ended (or the scanner gave up) before the handshake did. */
  end(reason: 'closed' | 'timeout', detail?: string) {
    if (this.done) return;
    const waitedFor = this.state === 'hello' ? undefined : `after the ServerHello: ${detail ?? (reason === 'timeout' ? 'timed out' : 'connection closed')}`;
    this.finish(waitedFor ? 'server-hello' : reason, waitedFor ?? detail);
  }

  private finish(outcome: HandshakeOutcome, detail?: string) {
    this.observation.outcome = outcome;
    if (detail) this.observation.detail = detail;
    this.state = 'done';
  }

  private onRecord(record: TlsRecord) {
    switch (record.type) {
      case CONTENT_TYPE.changeCipherSpec:
        return; // sent for middlebox compatibility; carries nothing
      case CONTENT_TYPE.alert:
        return this.onAlert(record.fragment);
      case CONTENT_TYPE.handshake:
        if (this.state === 'tls13') throw new WireError('plaintext handshake record after a TLS 1.3 ServerHello');
        this.plain.push(record.fragment);
        for (let message = this.plain.next(); message && !this.done; message = this.plain.next()) this.onPlainMessage(message);
        return;
      case CONTENT_TYPE.applicationData: {
        if (this.state !== 'tls13' || !this.protection) throw new WireError('encrypted record before a TLS 1.3 ServerHello');
        const inner = this.decrypt(record, this.protection);
        if (inner.type === CONTENT_TYPE.alert) return this.onAlert(inner.content);
        if (inner.type !== CONTENT_TYPE.handshake) throw new WireError(`unexpected content type ${inner.type} in the handshake`);
        this.decrypted.push(inner.content);
        for (let message = this.decrypted.next(); message && !this.done; message = this.decrypted.next()) this.onEncryptedMessage(message);
        return;
      }
    }
  }

  private onAlert(fragment: Buffer) {
    if (fragment.length < 2) throw new WireError('truncated alert');
    const [level, description] = [fragment[0]!, fragment[1]!];
    this.observation.alert = { level, description, name: alertName(description) };
    // An alert after the ServerHello does not undo what the ServerHello showed.
    this.finish(this.state === 'hello' ? 'alert' : 'server-hello', this.state === 'hello' ? undefined : `server sent ${alertName(description)} after its ServerHello`);
  }

  // ---- plaintext messages: ServerHello, and the whole TLS 1.2 flight ----

  private onPlainMessage(message: HandshakeMessage) {
    if (this.state === 'hello') {
      if (message.type !== HANDSHAKE_TYPE.serverHello) throw new WireError(`expected a ServerHello, got handshake type ${message.type}`);
      return this.onServerHello(message);
    }
    const body = new Reader(message.body);
    switch (message.type) {
      case HANDSHAKE_TYPE.certificate: {
        const list = new Reader(body.vector(3));
        const certificates: Buffer[] = [];
        while (list.remaining > 0) certificates.push(Buffer.from(list.vector(3)));
        this.observation.certificates = certificates;
        return;
      }
      case HANDSHAKE_TYPE.serverKeyExchange:
        return this.onServerKeyExchange(message.body);
      case HANDSHAKE_TYPE.certificateRequest:
        this.observation.clientCertificateRequested = true;
        return;
      case HANDSHAKE_TYPE.serverHelloDone:
        return this.finish('handshake');
      default:
        return; // CertificateStatus and anything else carry nothing this scanner reports
    }
  }

  private onServerHello(message: HandshakeMessage) {
    const body = new Reader(message.body);
    const legacyVersion = body.u16();
    const random = body.bytes(32);
    body.vector(1); // session ID echo
    const cipherSuite = body.u16();
    body.u8(); // compression method
    let selectedVersion: number | undefined;
    let share: { group: number; keyExchange?: Buffer } | undefined;
    if (body.remaining > 0) {
      const extensions = new Reader(body.vector(2));
      while (extensions.remaining > 0) {
        const type = extensions.u16();
        const data = new Reader(extensions.vector(2));
        if (type === EXTENSION.supportedVersions) selectedVersion = data.u16();
        else if (type === EXTENSION.keyShare) share = { group: data.u16(), keyExchange: data.remaining > 0 ? data.vector(2) : undefined };
        else if (type === EXTENSION.alpn) this.observation.alpn = readAlpn(data);
      }
    }

    const version = selectedVersion ?? legacyVersion;
    Object.assign(this.observation, { version, cipherSuite });
    this.serverRandom = Buffer.from(random);

    if (random.equals(HELLO_RETRY_RANDOM)) {
      if (!share) throw new WireError('HelloRetryRequest without a key_share extension');
      this.observation.group = share.group;
      return this.finish('hello-retry-request');
    }
    if (version !== 0x0304) {
      this.state = 'tls12';
      return;
    }

    // TLS 1.3: finish the key exchange so the rest of the flight can be read.
    if (!share?.keyExchange) throw new WireError('TLS 1.3 ServerHello without a key share');
    this.observation.group = share.group;
    this.transcript.push(message.raw);
    const suite = CIPHER_SUITES[cipherSuite];
    const aead = suite?.protocol === '1.3' ? AEAD[suite.cipher] : undefined;
    if (!suite || !aead || suite.hash === 'sha1') {
      return this.finish('server-hello', 'the server chose a cipher suite this scanner cannot decrypt');
    }
    const ours = this.keyShares.find((k) => k.group === share.group);
    if (!ours) throw new WireError('the server answered in a group no key share was sent for, without a HelloRetryRequest');

    const secrets = handshakeSecrets(suite.hash, ours.sharedSecret(share.keyExchange), transcriptHash(suite.hash, ...this.transcript));
    this.protection = {
      hash: suite.hash,
      algorithm: aead.algorithm,
      ...trafficKeys(suite.hash, secrets.serverHandshakeTraffic, aead.keyLength),
      serverTrafficSecret: secrets.serverHandshakeTraffic,
      sequence: 0,
    };
    this.state = 'tls13';
  }

  private onServerKeyExchange(raw: Buffer) {
    const suite = CIPHER_SUITES[this.observation.cipherSuite ?? -1];
    const body = new Reader(raw);
    let paramsLength: number;
    if (suite?.keyExchange === 'ECDHE') {
      if (body.u8() !== 3) return; // only named curves are in use
      this.observation.group = body.u16();
      body.vector(1); // the server's ephemeral point
      paramsLength = raw.length - body.remaining;
    } else if (suite?.keyExchange === 'DHE') {
      const prime = body.vector(2);
      body.vector(2); // generator
      body.vector(2); // the server's public value
      this.observation.dhPrimeBits = bitLength(prime);
      paramsLength = raw.length - body.remaining;
    } else {
      return;
    }
    if (body.remaining < 4) return;
    const scheme = body.u16();
    const signature = body.vector(2);
    this.observation.signatureScheme = scheme;
    // TLS 1.2 signs the two randoms and the parameters (RFC 5246 §7.4.3).
    const signed = Buffer.concat([this.clientHello.random, this.serverRandom, raw.subarray(0, paramsLength)]);
    this.observation.signatureValid = this.verifyLeafSignature(scheme, signed, signature, false);
  }

  // ---- TLS 1.3 encrypted flight ----

  private decrypt(record: TlsRecord, protection: Protection): { type: number; content: Buffer } {
    if (record.fragment.length < 17) throw new WireError('encrypted record too short');
    const tagAt = record.fragment.length - 16;
    const decipher = crypto.createDecipheriv(protection.algorithm, protection.key, recordNonce(protection.iv, protection.sequence++), {
      authTagLength: 16,
    });
    decipher.setAAD(record.header, { plaintextLength: tagAt });
    decipher.setAuthTag(record.fragment.subarray(tagAt));
    let plaintext: Buffer;
    try {
      plaintext = Buffer.concat([decipher.update(record.fragment.subarray(0, tagAt)), decipher.final()]);
    } catch {
      throw new WireError('the server’s handshake records did not decrypt with the negotiated keys');
    }
    // TLSInnerPlaintext: content, then the real content type, then optional zero padding.
    let end = plaintext.length;
    while (end > 0 && plaintext[end - 1] === 0) end--;
    if (end === 0) throw new WireError('encrypted record with no content type');
    return { type: plaintext[end - 1]!, content: plaintext.subarray(0, end - 1) };
  }

  private onEncryptedMessage(message: HandshakeMessage) {
    const { hash, serverTrafficSecret } = this.protection!;
    const body = new Reader(message.body);
    switch (message.type) {
      case HANDSHAKE_TYPE.encryptedExtensions: {
        const extensions = new Reader(body.vector(2));
        while (extensions.remaining > 0) {
          const type = extensions.u16();
          const data = new Reader(extensions.vector(2));
          if (type === EXTENSION.alpn) this.observation.alpn = readAlpn(data);
          else if (type === EXTENSION.supportedGroups) {
            const list = new Reader(data.vector(2));
            const groups: number[] = [];
            while (list.remaining >= 2) groups.push(list.u16());
            this.observation.serverGroups = groups;
          }
        }
        break;
      }
      case HANDSHAKE_TYPE.certificateRequest:
        this.observation.clientCertificateRequested = true;
        break;
      case HANDSHAKE_TYPE.certificate: {
        body.vector(1); // certificate_request_context, empty for a server certificate
        const list = new Reader(body.vector(3));
        const certificates: Buffer[] = [];
        while (list.remaining > 0) {
          certificates.push(Buffer.from(list.vector(3)));
          list.vector(2); // per-certificate extensions (OCSP staple, SCTs)
        }
        this.observation.certificates = certificates;
        break;
      }
      case HANDSHAKE_TYPE.certificateVerify: {
        const scheme = body.u16();
        const signature = body.vector(2);
        this.observation.signatureScheme = scheme;
        // The signature covers everything up to and including Certificate.
        const signed = Buffer.from(certificateVerifyInput(transcriptHash(hash, ...this.transcript)));
        this.observation.signatureValid = this.verifyLeafSignature(scheme, signed, signature, true);
        break;
      }
      case HANDSHAKE_TYPE.finished: {
        const expected = finishedVerifyData(hash, serverTrafficSecret, transcriptHash(hash, ...this.transcript));
        this.observation.finishedValid = message.body.length === expected.length && crypto.timingSafeEqual(message.body, expected);
        return this.finish('handshake');
      }
      default:
        break;
    }
    this.transcript.push(message.raw);
  }

  /** True or false when the check could be made; undefined when the key or scheme is one this scanner cannot use. */
  private verifyLeafSignature(schemeId: number, data: Buffer, signature: Buffer, tls13: boolean): boolean | undefined {
    const scheme = SIGNATURE_SCHEMES[schemeId];
    const leaf = this.observation.certificates?.[0];
    if (!scheme || !leaf) return undefined;
    let key: crypto.KeyObject;
    try {
      key = new crypto.X509Certificate(leaf).publicKey;
    } catch {
      return undefined;
    }
    const type = key.asymmetricKeyType ?? '';
    try {
      switch (scheme.family) {
        case 'RSA': {
          if (type !== 'rsa' && type !== 'rsa-pss') return false;
          const padding = scheme.padding === 'pss' ? crypto.constants.RSA_PKCS1_PSS_PADDING : crypto.constants.RSA_PKCS1_PADDING;
          return crypto.verify(scheme.hash, data, { key, padding, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature);
        }
        case 'ECDSA':
          if (type !== 'ec') return false;
          // TLS 1.3 ties each ECDSA scheme to one curve; TLS 1.2 does not.
          if (tls13 && scheme.curve && key.asymmetricKeyDetails?.namedCurve !== scheme.curve) return false;
          return crypto.verify(scheme.hash, data, key, signature);
        case 'EdDSA':
          return type === scheme.name && crypto.verify(null, data, key, signature);
        case 'ML-DSA':
          return type === scheme.name.replace('mldsa', 'ml-dsa-') && crypto.verify(null, data, key, signature);
      }
    } catch {
      return false;
    }
  }
}

function readAlpn(data: Reader): string | undefined {
  const list = new Reader(data.vector(2));
  return list.remaining > 0 ? list.vector(1).toString('ascii') : undefined;
}

function bitLength(value: Buffer): number {
  let i = 0;
  while (i < value.length && value[i] === 0) i++;
  if (i === value.length) return 0;
  return (value.length - i) * 8 - Math.clz32(value[i]!) + 24;
}
