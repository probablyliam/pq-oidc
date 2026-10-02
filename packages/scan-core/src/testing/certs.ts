/**
 * Issues X.509 certificates for the local test servers, using nothing but
 * Node's crypto and a few lines of DER. No OpenSSL command line and no
 * certificate library, which matters because the lab needs ML-DSA
 * certificates and most tooling cannot make them yet.
 *
 * For tests and local demonstrations only. These certificates chain to a CA
 * that exists for the lifetime of one process.
 */
import crypto from 'node:crypto';
import net from 'node:net';
import { parseIpv6 } from '../net/address.ts';

export type KeySpec =
  | { type: 'ec'; curve: 'P-256' | 'P-384' }
  | { type: 'rsa'; bits: 2048 | 3072 }
  | { type: 'ed25519' }
  | { type: 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87' };

export interface Certificate {
  der: Buffer;
  certPem: string;
  keyPem: string;
  subject: string;
  key: KeySpec;
  privateKey: crypto.KeyObject;
}

export interface IssueOptions {
  subject: string;
  key: KeySpec;
  /** DNS names and IP addresses for subjectAltName. */
  names?: string[];
  /** Signs the certificate. Omit for a self-signed certificate. */
  issuer?: Certificate;
  ca?: boolean;
  notBefore?: Date;
  notAfter?: Date;
  /** Digest for RSA and ECDSA signatures. SHA-1 exists so a test server can show a deprecated chain. */
  digest?: 'sha256' | 'sha384' | 'sha1';
}

// ---- DER ----

function length(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag: number, ...parts: Uint8Array[]): Buffer => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), length(body.length), body]);
};
const sequence = (...parts: Uint8Array[]) => tlv(0x30, ...parts);
const set = (...parts: Uint8Array[]) => tlv(0x31, ...parts);
const octetString = (value: Uint8Array) => tlv(0x04, value);
const bitString = (value: Uint8Array) => tlv(0x03, Buffer.from([0]), value);
const utf8String = (value: string) => tlv(0x0c, Buffer.from(value, 'utf8'));
const boolean = (value: boolean) => tlv(0x01, Buffer.from([value ? 0xff : 0]));
const NULL = Buffer.from([0x05, 0x00]);
const integer = (value: Uint8Array) => tlv(0x02, value[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value);
/** UTCTime: valid for the years 1950 to 2049, which covers any test certificate. */
const utcTime = (date: Date) => tlv(0x17, Buffer.from(`${date.toISOString().replace(/[-:T]/g, '').slice(2, 14)}Z`, 'ascii'));

function oid(dotted: string): Buffer {
  const arcs = dotted.split('.').map(Number);
  const bytes = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const chunk = [arc & 0x7f];
    for (let v = arc >>> 7; v > 0; v >>>= 7) chunk.unshift((v & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

const name = (commonName: string) => sequence(set(sequence(oid('2.5.4.3'), utf8String(commonName))));

// ---- keys and signature algorithms ----

function generate(key: KeySpec): crypto.KeyPairKeyObjectResult {
  switch (key.type) {
    case 'ec':
      return crypto.generateKeyPairSync('ec', { namedCurve: key.curve });
    case 'rsa':
      return crypto.generateKeyPairSync('rsa', { modulusLength: key.bits });
    case 'ed25519':
      return crypto.generateKeyPairSync('ed25519');
    default:
      // ML-DSA key generation is in Node 24.7+ but not yet in its type definitions.
      return crypto.generateKeyPairSync(key.type as 'ed25519');
  }
}

const RSA_DIGEST_OID = { sha1: '1.2.840.113549.1.1.5', sha256: '1.2.840.113549.1.1.11', sha384: '1.2.840.113549.1.1.12' };
const ECDSA_DIGEST_OID = { sha1: '1.2.840.10045.4.1', sha256: '1.2.840.10045.4.3.2', sha384: '1.2.840.10045.4.3.3' };
const ML_DSA_OID = { 'ml-dsa-44': '2.16.840.1.101.3.4.3.17', 'ml-dsa-65': '2.16.840.1.101.3.4.3.18', 'ml-dsa-87': '2.16.840.1.101.3.4.3.19' };

/** The AlgorithmIdentifier and signing function for a certificate signed with `key`. */
function signer(key: KeySpec, privateKey: crypto.KeyObject, digest: 'sha256' | 'sha384' | 'sha1') {
  switch (key.type) {
    case 'rsa':
      return { algorithm: sequence(oid(RSA_DIGEST_OID[digest]), NULL), sign: (tbs: Buffer) => crypto.sign(digest, tbs, privateKey) };
    case 'ec':
      return { algorithm: sequence(oid(ECDSA_DIGEST_OID[digest])), sign: (tbs: Buffer) => crypto.sign(digest, tbs, privateKey) };
    case 'ed25519':
      return { algorithm: sequence(oid('1.3.101.112')), sign: (tbs: Buffer) => crypto.sign(null, tbs, privateKey) };
    default:
      // Pure ML-DSA with an empty context, as FIPS 204 and the LAMPS certificate profile specify.
      return { algorithm: sequence(oid(ML_DSA_OID[key.type])), sign: (tbs: Buffer) => crypto.sign(null, tbs, privateKey) };
  }
}

function subjectAltName(names: string[]): Buffer {
  const entries = names.map((entry) => {
    const family = net.isIP(entry);
    if (family === 4) return tlv(0x87, Buffer.from(entry.split('.').map(Number)));
    if (family === 6) return tlv(0x87, Buffer.from(parseIpv6(entry)!));
    return tlv(0x82, Buffer.from(entry, 'ascii'));
  });
  return sequence(oid('2.5.29.17'), octetString(sequence(...entries)));
}

export function issueCertificate(options: IssueOptions): Certificate {
  const { publicKey, privateKey } = generate(options.key);
  const signingKey = options.issuer ?? { key: options.key, privateKey, subject: options.subject };
  const { algorithm, sign } = signer(signingKey.key, signingKey.privateKey, options.digest ?? 'sha256');

  const now = Date.now();
  const extensions = [sequence(oid('2.5.29.19'), boolean(true), octetString(options.ca ? sequence(boolean(true)) : sequence()))];
  if (options.names?.length) extensions.push(subjectAltName(options.names));
  if (options.ca) extensions.push(sequence(oid('2.5.29.15'), boolean(true), octetString(tlv(0x03, Buffer.from([0x01, 0x06]))))); // keyCertSign, cRLSign

  const tbs = sequence(
    tlv(0xa0, integer(Buffer.from([2]))), // v3
    integer(Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(15)])),
    algorithm,
    name(signingKey.subject),
    sequence(utcTime(options.notBefore ?? new Date(now - 3600_000)), utcTime(options.notAfter ?? new Date(now + 90 * 86_400_000))),
    name(options.subject),
    publicKey.export({ type: 'spki', format: 'der' }),
    tlv(0xa3, sequence(...extensions)),
  );
  const der = sequence(tbs, algorithm, bitString(sign(tbs)));

  return {
    der,
    certPem: `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`,
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    subject: options.subject,
    key: options.key,
    privateKey,
  };
}
