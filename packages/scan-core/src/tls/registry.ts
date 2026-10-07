/**
 * Names and properties for the TLS code points the scanner offers and
 * recognises. Sources: the IANA TLS parameters registry, RFC 8446,
 * RFC 10024 (hybrid groups), draft-ietf-tls-mlkem (pure ML-KEM groups) and
 * draft-ietf-tls-mldsa (ML-DSA signature schemes). The registry is the
 * authority for the numbers; the documents say what they mean.
 *
 * No Node APIs: the web app uses these tables to name what a report contains.
 */

/** How a key-establishment group stands against a quantum attacker. */
export type KexClass = 'classical' | 'hybrid' | 'pq';

export interface GroupInfo {
  id: number;
  name: string;
  kex: KexClass;
  /** The primitives inside, e.g. ["X25519", "ML-KEM-768"]. */
  components: string[];
  /** Superseded pre-standard code point. */
  draft?: boolean;
}

const group = (id: number, name: string, kex: KexClass, components: string[], draft?: boolean): GroupInfo => ({ id, name, kex, components, draft });

export const GROUP = {
  secp256r1: 0x0017,
  secp384r1: 0x0018,
  secp521r1: 0x0019,
  x25519: 0x001d,
  x448: 0x001e,
  ffdhe2048: 0x0100,
  ffdhe3072: 0x0101,
  MLKEM512: 0x0200,
  MLKEM768: 0x0201,
  MLKEM1024: 0x0202,
  SecP256r1MLKEM768: 0x11eb,
  X25519MLKEM768: 0x11ec,
  SecP384r1MLKEM1024: 0x11ed,
  X25519Kyber768Draft00: 0x6399,
} as const;

export const GROUPS: Record<number, GroupInfo> = Object.fromEntries(
  [
    group(GROUP.secp256r1, 'secp256r1', 'classical', ['ECDH P-256']),
    group(GROUP.secp384r1, 'secp384r1', 'classical', ['ECDH P-384']),
    group(GROUP.secp521r1, 'secp521r1', 'classical', ['ECDH P-521']),
    group(GROUP.x25519, 'x25519', 'classical', ['X25519']),
    group(GROUP.x448, 'x448', 'classical', ['X448']),
    group(GROUP.ffdhe2048, 'ffdhe2048', 'classical', ['Finite-field DH 2048-bit']),
    group(GROUP.ffdhe3072, 'ffdhe3072', 'classical', ['Finite-field DH 3072-bit']),
    group(0x0102, 'ffdhe4096', 'classical', ['Finite-field DH 4096-bit']),
    group(GROUP.MLKEM512, 'MLKEM512', 'pq', ['ML-KEM-512']),
    group(GROUP.MLKEM768, 'MLKEM768', 'pq', ['ML-KEM-768']),
    group(GROUP.MLKEM1024, 'MLKEM1024', 'pq', ['ML-KEM-1024']),
    group(GROUP.SecP256r1MLKEM768, 'SecP256r1MLKEM768', 'hybrid', ['ECDH P-256', 'ML-KEM-768']),
    group(GROUP.X25519MLKEM768, 'X25519MLKEM768', 'hybrid', ['X25519', 'ML-KEM-768']),
    group(GROUP.SecP384r1MLKEM1024, 'SecP384r1MLKEM1024', 'hybrid', ['ECDH P-384', 'ML-KEM-1024']),
    group(0x11ee, 'curveSM2MLKEM768', 'hybrid', ['SM2', 'ML-KEM-768']),
    group(GROUP.X25519Kyber768Draft00, 'X25519Kyber768Draft00', 'hybrid', ['X25519', 'Kyber-768 (round 3)'], true),
    group(0x639a, 'SecP256r1Kyber768Draft00', 'hybrid', ['ECDH P-256', 'Kyber-768 (round 3)'], true),
  ].map((g) => [g.id, g]),
);

export function groupName(id: number): string {
  return GROUPS[id]?.name ?? `unknown group 0x${id.toString(16).padStart(4, '0')}`;
}

/** The post-quantum and hybrid groups the scanner asks about one by one. */
export const PQ_GROUPS_TO_ENUMERATE: readonly number[] = [
  GROUP.X25519MLKEM768,
  GROUP.SecP256r1MLKEM768,
  GROUP.SecP384r1MLKEM1024,
  GROUP.MLKEM768,
  GROUP.MLKEM1024,
];

export type KeyExchangeKind = 'ECDHE' | 'DHE' | 'RSA';

export interface CipherSuiteInfo {
  id: number;
  name: string;
  protocol: '1.3' | '1.2';
  /** TLS 1.2 only: how the session key is established. In TLS 1.3 that is the group's job. */
  keyExchange?: KeyExchangeKind;
  /** TLS 1.2 only: the certificate key type the suite requires. */
  authentication?: 'RSA' | 'ECDSA';
  cipher: string;
  /** Symmetric key size in bits. */
  keyBits: number;
  aead: boolean;
  /** Hash for the TLS 1.3 key schedule (or the TLS 1.2 PRF). */
  hash: 'sha256' | 'sha384' | 'sha1';
}

const suite13 = (id: number, name: string, cipher: string, keyBits: number, hash: 'sha256' | 'sha384'): CipherSuiteInfo => ({
  id,
  name,
  protocol: '1.3',
  cipher,
  keyBits,
  aead: true,
  hash,
});

function suite12(id: number, name: string): CipherSuiteInfo {
  // TLS_<kex>_<auth>_WITH_<cipher>_<mac/prf>, or TLS_RSA_WITH_… for RSA key transport.
  const [left = '', right = ''] = name.replace(/^TLS_/, '').split('_WITH_');
  const [kex, auth] = left.split('_');
  const keyExchange: KeyExchangeKind = kex === 'ECDHE' ? 'ECDHE' : kex === 'DHE' ? 'DHE' : 'RSA';
  const aead = /GCM|POLY1305|CCM/.test(right);
  return {
    id,
    name,
    protocol: '1.2',
    keyExchange,
    authentication: (auth ?? kex) === 'ECDSA' ? 'ECDSA' : 'RSA',
    cipher: right.replace(/_SHA\d*$/, '').replaceAll('_', '-'),
    keyBits: /AES_256|CHACHA20/.test(right) ? 256 : /3DES/.test(right) ? 112 : 128,
    aead,
    hash: right.endsWith('SHA384') ? 'sha384' : aead || right.endsWith('SHA256') ? 'sha256' : 'sha1',
  };
}

export const CIPHER_SUITES: Record<number, CipherSuiteInfo> = Object.fromEntries(
  [
    suite13(0x1301, 'TLS_AES_128_GCM_SHA256', 'AES-128-GCM', 128, 'sha256'),
    suite13(0x1302, 'TLS_AES_256_GCM_SHA384', 'AES-256-GCM', 256, 'sha384'),
    suite13(0x1303, 'TLS_CHACHA20_POLY1305_SHA256', 'CHACHA20-POLY1305', 256, 'sha256'),
    suite12(0xc02b, 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
    suite12(0xc02c, 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'),
    suite12(0xc02f, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
    suite12(0xc030, 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'),
    suite12(0xcca8, 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'),
    suite12(0xcca9, 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'),
    suite12(0xc009, 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'),
    suite12(0xc00a, 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'),
    suite12(0xc013, 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'),
    suite12(0xc014, 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'),
    suite12(0xc027, 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'),
    suite12(0xc028, 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'),
    suite12(0x009e, 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'),
    suite12(0x009f, 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'),
    suite12(0x0033, 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'),
    suite12(0x0039, 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA'),
    suite12(0x009c, 'TLS_RSA_WITH_AES_128_GCM_SHA256'),
    suite12(0x009d, 'TLS_RSA_WITH_AES_256_GCM_SHA384'),
    suite12(0x002f, 'TLS_RSA_WITH_AES_128_CBC_SHA'),
    suite12(0x0035, 'TLS_RSA_WITH_AES_256_CBC_SHA'),
    suite12(0x003c, 'TLS_RSA_WITH_AES_128_CBC_SHA256'),
    suite12(0x003d, 'TLS_RSA_WITH_AES_256_CBC_SHA256'),
  ].map((s) => [s.id, s]),
);

export const TLS13_SUITES: readonly number[] = [0x1302, 0x1301, 0x1303];
/** Offered to TLS 1.2 servers, forward-secret suites first, RSA key transport last. */
export const TLS12_SUITES: readonly number[] = [
  0xc02c, 0xc030, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0x009f, 0x009e, 0xc00a, 0xc014, 0xc009, 0xc013, 0xc028, 0xc027, 0x0039, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c,
  0x0035, 0x002f,
];

export function cipherSuiteName(id: number): string {
  return CIPHER_SUITES[id]?.name ?? `unknown suite 0x${id.toString(16).padStart(4, '0')}`;
}

export type SignatureFamily = 'RSA' | 'ECDSA' | 'EdDSA' | 'ML-DSA';

export interface SignatureSchemeInfo {
  id: number;
  name: string;
  family: SignatureFamily;
  /** No known quantum attack on the signature algorithm. */
  quantumSafe: boolean;
  /** Digest applied before signing; undefined when the algorithm hashes internally. */
  hash?: 'sha1' | 'sha256' | 'sha384' | 'sha512';
  padding?: 'pkcs1' | 'pss';
  /** TLS 1.3 fixes the curve for ECDSA schemes. */
  curve?: string;
}

const scheme = (id: number, name: string, family: SignatureFamily, extra: Partial<SignatureSchemeInfo> = {}): SignatureSchemeInfo => ({
  id,
  name,
  family,
  quantumSafe: family === 'ML-DSA',
  ...extra,
});

export const SIGNATURE_SCHEMES: Record<number, SignatureSchemeInfo> = Object.fromEntries(
  [
    scheme(0x0904, 'mldsa44', 'ML-DSA'),
    scheme(0x0905, 'mldsa65', 'ML-DSA'),
    scheme(0x0906, 'mldsa87', 'ML-DSA'),
    scheme(0x0403, 'ecdsa_secp256r1_sha256', 'ECDSA', { hash: 'sha256', curve: 'prime256v1' }),
    scheme(0x0503, 'ecdsa_secp384r1_sha384', 'ECDSA', { hash: 'sha384', curve: 'secp384r1' }),
    scheme(0x0603, 'ecdsa_secp521r1_sha512', 'ECDSA', { hash: 'sha512', curve: 'secp521r1' }),
    scheme(0x0807, 'ed25519', 'EdDSA'),
    scheme(0x0808, 'ed448', 'EdDSA'),
    scheme(0x0804, 'rsa_pss_rsae_sha256', 'RSA', { hash: 'sha256', padding: 'pss' }),
    scheme(0x0805, 'rsa_pss_rsae_sha384', 'RSA', { hash: 'sha384', padding: 'pss' }),
    scheme(0x0806, 'rsa_pss_rsae_sha512', 'RSA', { hash: 'sha512', padding: 'pss' }),
    scheme(0x0809, 'rsa_pss_pss_sha256', 'RSA', { hash: 'sha256', padding: 'pss' }),
    scheme(0x080a, 'rsa_pss_pss_sha384', 'RSA', { hash: 'sha384', padding: 'pss' }),
    scheme(0x080b, 'rsa_pss_pss_sha512', 'RSA', { hash: 'sha512', padding: 'pss' }),
    scheme(0x0401, 'rsa_pkcs1_sha256', 'RSA', { hash: 'sha256', padding: 'pkcs1' }),
    scheme(0x0501, 'rsa_pkcs1_sha384', 'RSA', { hash: 'sha384', padding: 'pkcs1' }),
    scheme(0x0601, 'rsa_pkcs1_sha512', 'RSA', { hash: 'sha512', padding: 'pkcs1' }),
    scheme(0x0201, 'rsa_pkcs1_sha1', 'RSA', { hash: 'sha1', padding: 'pkcs1' }),
    scheme(0x0203, 'ecdsa_sha1', 'ECDSA', { hash: 'sha1' }),
  ].map((s) => [s.id, s]),
);

/** What a client that understands ML-DSA offers, most preferred first. */
export const SIGNATURE_SCHEMES_WITH_PQ: readonly number[] = [
  0x0905, 0x0904, 0x0906, 0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b, 0x0401, 0x0501, 0x0601,
];
/** What a client without post-quantum support offers. SHA-1 schemes come last so a server using one is seen, not hidden. */
export const SIGNATURE_SCHEMES_CLASSICAL: readonly number[] = [
  0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];

export function signatureSchemeName(id: number): string {
  return SIGNATURE_SCHEMES[id]?.name ?? `unknown scheme 0x${id.toString(16).padStart(4, '0')}`;
}

const ALERTS: Record<number, string> = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  22: 'record_overflow',
  40: 'handshake_failure',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  49: 'access_denied',
  50: 'decode_error',
  51: 'decrypt_error',
  70: 'protocol_version',
  71: 'insufficient_security',
  80: 'internal_error',
  86: 'inappropriate_fallback',
  90: 'user_canceled',
  109: 'missing_extension',
  110: 'unsupported_extension',
  112: 'unrecognized_name',
  116: 'certificate_required',
  120: 'no_application_protocol',
};

export function alertName(description: number): string {
  return ALERTS[description] ?? `alert ${description}`;
}

const VERSIONS: Record<number, string> = { 0x0304: '1.3', 0x0303: '1.2', 0x0302: '1.1', 0x0301: '1.0', 0x0300: 'SSL 3.0' };

export function versionName(id: number): string {
  return VERSIONS[id] ?? `0x${id.toString(16).padStart(4, '0')}`;
}
