/**
 * Facts about the signature algorithms this project compares.
 *
 * Sizes are fixed by the standards, so they are constants rather than measurements:
 * - ML-DSA sizes come from FIPS 204, Table 2.
 * - ES256 is ECDSA P-256 (FIPS 186-5); a JWS signature is r || s = 64 bytes (RFC 7518 §3.4).
 * - RS256 uses a 2048-bit RSA key, so signatures are 256 bytes.
 *
 * This file has no dependencies so both the Node packages and the browser lab can import it.
 */

export type SigningAlg = 'ES256' | 'RS256' | 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export interface AlgorithmInfo {
  alg: SigningAlg;
  /** Human-readable name of the underlying scheme. */
  scheme: string;
  /** The documents that define the algorithm and its JOSE encoding. */
  standard: string;
  /** Raw signature length in bytes (before base64url encoding). */
  signatureBytes: number;
  /** Raw public key length in bytes. */
  publicKeyBytes: number;
  /** Does it resist a large quantum computer running Shor's algorithm? */
  quantumSafe: boolean;
  /** NIST security category (1–5) for post-quantum schemes; null for classical ones. */
  nistCategory: number | null;
}

export const ALGORITHMS: Record<SigningAlg, AlgorithmInfo> = {
  ES256: {
    alg: 'ES256',
    scheme: 'ECDSA with P-256 and SHA-256',
    standard: 'FIPS 186-5 / RFC 7518',
    signatureBytes: 64,
    publicKeyBytes: 64,
    quantumSafe: false,
    nistCategory: null,
  },
  RS256: {
    alg: 'RS256',
    scheme: 'RSASSA-PKCS1-v1_5 (2048-bit) with SHA-256',
    standard: 'RFC 8017 / RFC 7518',
    signatureBytes: 256,
    publicKeyBytes: 256,
    quantumSafe: false,
    nistCategory: null,
  },
  'ML-DSA-44': {
    alg: 'ML-DSA-44',
    scheme: 'Module-Lattice-Based Digital Signature Algorithm, parameter set 44',
    standard: 'FIPS 204 / RFC 9964',
    signatureBytes: 2420,
    publicKeyBytes: 1312,
    quantumSafe: true,
    nistCategory: 2,
  },
  'ML-DSA-65': {
    alg: 'ML-DSA-65',
    scheme: 'Module-Lattice-Based Digital Signature Algorithm, parameter set 65',
    standard: 'FIPS 204 / RFC 9964',
    signatureBytes: 3309,
    publicKeyBytes: 1952,
    quantumSafe: true,
    nistCategory: 3,
  },
  'ML-DSA-87': {
    alg: 'ML-DSA-87',
    scheme: 'Module-Lattice-Based Digital Signature Algorithm, parameter set 87',
    standard: 'FIPS 204 / RFC 9964',
    signatureBytes: 4627,
    publicKeyBytes: 2592,
    quantumSafe: true,
    nistCategory: 5,
  },
};

/**
 * Browsers drop a cookie whose name + value exceeds 4096 bytes.
 * RFC 6265 §6.1 sets 4096 bytes as the minimum user agents must support, and
 * Chrome, Firefox and Safari all use it as the maximum in practice.
 */
export const COOKIE_BYTE_LIMIT = 4096;

export function isSigningAlg(value: unknown): value is SigningAlg {
  return typeof value === 'string' && Object.hasOwn(ALGORITHMS, value);
}
