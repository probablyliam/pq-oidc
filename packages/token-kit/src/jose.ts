/**
 * What each JOSE algorithm name means, and how it stands against a quantum
 * computer. Kept precise on purpose: a signature, a MAC and key management
 * for encryption are different things with different risks.
 *
 * Sources: RFC 7518 (JWA), RFC 8037 (EdDSA), RFC 9964 (ML-DSA).
 */

export type JwsAlgKind = 'none' | 'hmac' | 'rsa-pkcs1' | 'rsa-pss' | 'ecdsa' | 'eddsa' | 'ml-dsa' | 'slh-dsa' | 'unknown';

/** What a capable quantum computer changes for an algorithm. */
export type QuantumStanding =
  /** Public-key scheme broken by Shor's algorithm. */
  | 'shor'
  /** Symmetric: Grover's algorithm weakens it, a long enough key keeps it safe. */
  | 'grover'
  | 'no-known-attack'
  /** Nothing to break: there is no protection. */
  | 'none'
  | 'unknown';

export interface JwsAlg {
  alg: string;
  kind: JwsAlgKind;
  /** The scheme in words, e.g. "ECDSA with P-256 and SHA-256". */
  name: string;
  /** A signature anyone can check with a public key, as opposed to a MAC or nothing. */
  publicKey: boolean;
  quantum: QuantumStanding;
  hash?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  curve?: 'P-256' | 'P-384' | 'P-521' | 'Ed25519';
}

const HASH = { '256': 'SHA-256', '384': 'SHA-384', '512': 'SHA-512' } as const;
const ES_CURVE = { '256': 'P-256', '384': 'P-384', '512': 'P-521' } as const;

export function describeJwsAlg(value: unknown): JwsAlg {
  const alg = typeof value === 'string' ? value : '';
  // RFC 7518 spells it "none"; verifiers have been fooled by other capitalisations.
  if (alg.toLowerCase() === 'none') return { alg, kind: 'none', name: 'no signature', publicKey: false, quantum: 'none' };

  const sized = /^(HS|RS|PS|ES)(256|384|512)$/.exec(alg);
  if (sized) {
    const [, family, bits] = sized as unknown as [string, 'HS' | 'RS' | 'PS' | 'ES', '256' | '384' | '512'];
    const hash = HASH[bits];
    if (family === 'HS') return { alg, kind: 'hmac', name: `HMAC with ${hash}`, publicKey: false, quantum: 'grover', hash };
    if (family === 'RS') return { alg, kind: 'rsa-pkcs1', name: `RSA PKCS#1 v1.5 with ${hash}`, publicKey: true, quantum: 'shor', hash };
    if (family === 'PS') return { alg, kind: 'rsa-pss', name: `RSA-PSS with ${hash}`, publicKey: true, quantum: 'shor', hash };
    return { alg, kind: 'ecdsa', name: `ECDSA with ${ES_CURVE[bits]} and ${hash}`, publicKey: true, quantum: 'shor', hash, curve: ES_CURVE[bits] };
  }
  if (alg === 'ES256K') return { alg, kind: 'ecdsa', name: 'ECDSA with secp256k1 and SHA-256', publicKey: true, quantum: 'shor', hash: 'SHA-256' };
  if (alg === 'EdDSA' || alg === 'Ed25519') return { alg, kind: 'eddsa', name: 'EdDSA (Ed25519)', publicKey: true, quantum: 'shor', curve: 'Ed25519' };
  if (alg === 'Ed448') return { alg, kind: 'eddsa', name: 'EdDSA (Ed448)', publicKey: true, quantum: 'shor' };
  if (/^ML-DSA-(44|65|87)$/.test(alg)) return { alg, kind: 'ml-dsa', name: `${alg} (FIPS 204)`, publicKey: true, quantum: 'no-known-attack' };
  if (/^SLH-DSA-/.test(alg)) return { alg, kind: 'slh-dsa', name: `${alg} (FIPS 205)`, publicKey: true, quantum: 'no-known-attack' };
  return { alg, kind: 'unknown', name: alg ? `unrecognised algorithm "${alg}"` : 'no algorithm named', publicKey: false, quantum: 'unknown' };
}

export interface JweAlg {
  alg: string;
  /** How the content-encryption key reaches the recipient. */
  name: string;
  quantum: QuantumStanding;
}

/** JWE key management ("alg" in a JWE header). This is key establishment, so harvest-now-decrypt-later applies. */
export function describeJweAlg(value: unknown): JweAlg {
  const alg = typeof value === 'string' ? value : '';
  if (/^RSA(1_5|-OAEP(-\d+)?)$/.test(alg)) return { alg, name: 'RSA encryption of the content key', quantum: 'shor' };
  if (/^ECDH-ES/.test(alg)) return { alg, name: 'Elliptic-curve Diffie-Hellman key agreement', quantum: 'shor' };
  if (alg === 'dir' || /^A(128|192|256)(GCM)?KW$/.test(alg) || /^PBES2-/.test(alg)) return { alg, name: 'a shared symmetric key', quantum: 'grover' };
  if (/^ML-KEM-/.test(alg)) return { alg, name: 'ML-KEM key encapsulation (FIPS 203)', quantum: 'no-known-attack' };
  return { alg, name: alg ? `unrecognised algorithm "${alg}"` : 'no algorithm named', quantum: 'unknown' };
}
