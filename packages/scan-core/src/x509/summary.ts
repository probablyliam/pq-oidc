/**
 * Summarises the certificates a server sent: who they name, how long they are
 * valid, the type of key they carry and the algorithm their issuer signed
 * them with. Parsing is OpenSSL's (through Node); nothing here decides trust.
 */
import crypto from 'node:crypto';
import type { CertificateSummary, SignatureFamilyName } from '../report.ts';

interface SignatureAlgorithm {
  name: string;
  family: SignatureFamilyName;
  hash?: string;
}

const RSA = '1.2.840.113549.1.1';
const ECDSA = '1.2.840.10045.4';
const NIST_SIG = '2.16.840.1.101.3.4.3';

const SIGNATURE_OIDS: Record<string, SignatureAlgorithm> = {
  [`${RSA}.4`]: { name: 'RSA PKCS#1 v1.5 with MD5', family: 'RSA', hash: 'MD5' },
  [`${RSA}.5`]: { name: 'RSA PKCS#1 v1.5 with SHA-1', family: 'RSA', hash: 'SHA-1' },
  [`${RSA}.11`]: { name: 'RSA PKCS#1 v1.5 with SHA-256', family: 'RSA', hash: 'SHA-256' },
  [`${RSA}.12`]: { name: 'RSA PKCS#1 v1.5 with SHA-384', family: 'RSA', hash: 'SHA-384' },
  [`${RSA}.13`]: { name: 'RSA PKCS#1 v1.5 with SHA-512', family: 'RSA', hash: 'SHA-512' },
  [`${RSA}.10`]: { name: 'RSASSA-PSS', family: 'RSA' },
  [`${ECDSA}.1`]: { name: 'ECDSA with SHA-1', family: 'ECDSA', hash: 'SHA-1' },
  [`${ECDSA}.3.2`]: { name: 'ECDSA with SHA-256', family: 'ECDSA', hash: 'SHA-256' },
  [`${ECDSA}.3.3`]: { name: 'ECDSA with SHA-384', family: 'ECDSA', hash: 'SHA-384' },
  [`${ECDSA}.3.4`]: { name: 'ECDSA with SHA-512', family: 'ECDSA', hash: 'SHA-512' },
  '1.3.101.112': { name: 'Ed25519', family: 'EdDSA' },
  '1.3.101.113': { name: 'Ed448', family: 'EdDSA' },
  [`${NIST_SIG}.17`]: { name: 'ML-DSA-44', family: 'ML-DSA' },
  [`${NIST_SIG}.18`]: { name: 'ML-DSA-65', family: 'ML-DSA' },
  [`${NIST_SIG}.19`]: { name: 'ML-DSA-87', family: 'ML-DSA' },
};

function signatureAlgorithm(oid: string, text: string): SignatureAlgorithm {
  const known = SIGNATURE_OIDS[oid];
  if (known) return known;
  // FIPS 205 assigns .20 to .31 to the twelve SLH-DSA parameter sets.
  const last = Number(oid.startsWith(`${NIST_SIG}.`) ? oid.slice(NIST_SIG.length + 1) : NaN);
  if (last >= 20 && last <= 31) return { name: text || 'SLH-DSA', family: 'SLH-DSA' };
  return { name: text || oid, family: 'unknown' };
}

const quantumSafe = (family: SignatureFamilyName) => family === 'ML-DSA' || family === 'SLH-DSA';

const CURVES: Record<string, string> = { prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521' };

function describeKey(certificate: crypto.X509Certificate): CertificateSummary['key'] {
  let key: crypto.KeyObject;
  try {
    key = certificate.publicKey;
  } catch {
    // A key type this OpenSSL build cannot load. Report that, rather than guess.
    return { algorithm: 'unrecognised key type', family: 'unknown', quantumSafe: false };
  }
  const type = String(key.asymmetricKeyType);
  const details = key.asymmetricKeyDetails;
  if (type === 'rsa' || type === 'rsa-pss') {
    return { algorithm: `RSA ${details?.modulusLength}-bit`, family: 'RSA', bits: details?.modulusLength, quantumSafe: false };
  }
  if (type === 'ec') {
    const curve = CURVES[details?.namedCurve ?? ''] ?? details?.namedCurve ?? 'unknown curve';
    return { algorithm: `ECDSA ${curve}`, family: 'ECDSA', curve, quantumSafe: false };
  }
  if (type === 'ed25519' || type === 'ed448') return { algorithm: type === 'ed25519' ? 'Ed25519' : 'Ed448', family: 'EdDSA', quantumSafe: false };
  if (type.startsWith('ml-dsa')) return { algorithm: type.toUpperCase(), family: 'ML-DSA', quantumSafe: true };
  if (type.startsWith('slh-dsa')) return { algorithm: type.toUpperCase(), family: 'SLH-DSA', quantumSafe: true };
  return { algorithm: type, family: 'unknown', quantumSafe: false };
}

function altNames(certificate: crypto.X509Certificate): string[] {
  return (certificate.subjectAltName ?? '')
    .split(', ')
    .filter(Boolean)
    .map((entry) => entry.replace(/^(DNS|IP Address|URI|email):/, ''));
}

function isSelfSigned(certificate: crypto.X509Certificate): boolean {
  if (certificate.subject !== certificate.issuer) return false;
  try {
    return certificate.verify(certificate.publicKey);
  } catch {
    return false;
  }
}

/** Distinguished names come back one attribute per line; a report wants one line. */
const oneLine = (name: string) => name.split('\n').reverse().join(', ');

export function summarizeCertificate(der: Buffer, position: number, now = new Date()): CertificateSummary {
  const certificate = new crypto.X509Certificate(der);
  const notBefore = new Date(certificate.validFrom);
  const notAfter = new Date(certificate.validTo);
  const signature = signatureAlgorithm(certificate.signatureAlgorithmOid ?? '', certificate.signatureAlgorithm ?? '');
  return {
    position,
    subject: oneLine(certificate.subject),
    issuer: oneLine(certificate.issuer),
    serialNumber: certificate.serialNumber,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    expired: notAfter < now,
    notYetValid: notBefore > now,
    selfSigned: isSelfSigned(certificate),
    isCa: certificate.ca,
    names: altNames(certificate),
    key: describeKey(certificate),
    signature: { algorithm: signature.name, oid: certificate.signatureAlgorithmOid ?? '', family: signature.family, hash: signature.hash, quantumSafe: quantumSafe(signature.family) },
    fingerprint256: crypto.createHash('sha256').update(der).digest('hex'),
    pem: certificate.toString(),
  };
}

/** Summarises a chain, skipping anything that does not parse as a certificate. */
export function summarizeChain(chain: Buffer[], now = new Date()): CertificateSummary[] {
  const out: CertificateSummary[] = [];
  for (const [position, der] of chain.entries()) {
    try {
      out.push(summarizeCertificate(der, position, now));
    } catch {
      // The handshake delivered bytes that are not a certificate; the count mismatch is visible in the report.
    }
  }
  return out;
}
