/**
 * The real cryptography behind the Login Lab.
 *
 * `runLogin` performs one login the way HTTPS and a login server do it, in a
 * simplified form, with real operations:
 *
 *   1. Key agreement    ECDH P-256 (Web Crypto), plus ML-KEM-768 (FIPS 203) in
 *                       the hybrid and post-quantum modes. Both sides end up
 *                       with the same shared secret.
 *   2. Server identity  The server signs the handshake with its private key;
 *                       the browser verifies with the public key.
 *   3. Encryption       The login request is encrypted with AES-256-GCM under
 *                       a key derived (HKDF) from the shared secret.
 *   4. Login token      The server signs a token (ES256 or ML-DSA-65, FIPS 204).
 *
 * What is NOT real: this is not a TLS implementation (the handshake is a
 * representative sketch of TLS 1.3), and `runAttack` does not break anything.
 * For "a quantum computer recovers the private key" it uses the private key
 * this module already holds, because that is what such a computer would
 * compute. Everything the attacker does with a recovered key is real.
 */
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { generateKey, signBytes, signJwt, verifyJwt, verifySignature } from '../crypto/jws.ts';
import type { LabKey } from '../crypto/jws.ts';

export type Mode = 'classical' | 'hybrid' | 'pq';
export type Computer = 'classical' | 'quantum';

export interface ModeInfo {
  id: Mode;
  label: string;
  blurb: string;
  keyAgreement: { name: string; standard: string; quantumSafe: boolean };
  signature: { alg: 'ES256' | 'ML-DSA-65'; name: string; standard: string; quantumSafe: boolean };
}

export const MODES: Record<Mode, ModeInfo> = {
  classical: {
    id: 'classical',
    label: 'Classical',
    blurb: 'How logins have worked for years.',
    keyAgreement: { name: 'ECDHE (P-256)', standard: 'TLS 1.3 group secp256r1', quantumSafe: false },
    signature: { alg: 'ES256', name: 'ECDSA (P-256)', standard: 'FIPS 186-5', quantumSafe: false },
  },
  hybrid: {
    id: 'hybrid',
    label: 'Hybrid connection',
    blurb: 'Where much of the web is now: a quantum-safe connection, classical signatures.',
    keyAgreement: { name: 'ECDHE (P-256) + ML-KEM-768', standard: 'TLS 1.3 group SecP256r1MLKEM768', quantumSafe: true },
    signature: { alg: 'ES256', name: 'ECDSA (P-256)', standard: 'FIPS 186-5', quantumSafe: false },
  },
  pq: {
    id: 'pq',
    label: 'Post-quantum',
    blurb: 'Quantum-safe key agreement and quantum-safe signatures.',
    keyAgreement: { name: 'ECDHE (P-256) + ML-KEM-768', standard: 'TLS 1.3 group SecP256r1MLKEM768', quantumSafe: true },
    signature: { alg: 'ML-DSA-65', name: 'ML-DSA-65', standard: 'FIPS 204', quantumSafe: true },
  },
};

export const LOGIN_REQUEST = 'POST /login\nusername=alice@example.com\npassword=correct-horse';
const ISSUER = 'https://payroll.example';
const AUDIENCE = 'payroll';
const HANDSHAKE_CONTEXT = 'pq-oidc lab handshake';

const encoder = new TextEncoder();
const ECDH = { name: 'ECDH', namedCurve: 'P-256' } as const;

export interface Session {
  mode: Mode;
  /** Key shares that cross the network in the clear. */
  wire: {
    browserEcdh: Uint8Array;
    serverEcdh: Uint8Array;
    kemPublicKey?: Uint8Array;
    kemCipherText?: Uint8Array;
    handshakeSignature: Uint8Array;
    iv: Uint8Array;
    encryptedRequest: Uint8Array;
  };
  /** The same value on both sides, never sent. */
  sharedSecret: { browser: Uint8Array; server: Uint8Array };
  serverKey: LabKey;
  handshakeVerified: boolean;
  /** What the server read after decrypting. */
  decryptedRequest: string;
  token: string;
  tokenVerified: boolean;
  /** Private values the demo holds so the conceptual attack has something to "recover". */
  held: { serverEcdhPrivate: CryptoKey; browserEcdhPublic: CryptoKey };
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

async function channelKey(secret: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode('login lab channel') },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function ecdhSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256));
}

const rawPublic = async (key: CryptoKey) => new Uint8Array(await crypto.subtle.exportKey('raw', key));

function tokenClaims() {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: AUDIENCE, sub: 'alice', name: 'Alice Nakamura', iat: now, exp: now + 3600 };
}

const verifyOptions = (mode: Mode) => ({ issuer: ISSUER, audience: AUDIENCE, algorithms: [MODES[mode].signature.alg] });

export async function runLogin(mode: Mode): Promise<Session> {
  const info = MODES[mode];
  const usesKem = mode !== 'classical';

  // 1. Key agreement. Each side makes a key pair and sends the public half.
  const browserPair = (await crypto.subtle.generateKey(ECDH, true, ['deriveBits'])) as CryptoKeyPair;
  const serverPair = (await crypto.subtle.generateKey(ECDH, true, ['deriveBits'])) as CryptoKeyPair;
  let browserSecret = await ecdhSecret(browserPair.privateKey, serverPair.publicKey);
  let serverSecret = await ecdhSecret(serverPair.privateKey, browserPair.publicKey);

  let kemPublicKey: Uint8Array | undefined;
  let kemCipherText: Uint8Array | undefined;
  if (usesKem) {
    // ML-KEM: the browser sends a public key; the server "encapsulates" a secret to it.
    const kem = ml_kem768.keygen();
    const encapsulated = ml_kem768.encapsulate(kem.publicKey);
    kemPublicKey = kem.publicKey;
    kemCipherText = encapsulated.cipherText;
    serverSecret = concat(serverSecret, encapsulated.sharedSecret);
    browserSecret = concat(browserSecret, ml_kem768.decapsulate(encapsulated.cipherText, kem.secretKey));
  }

  const browserEcdh = await rawPublic(browserPair.publicKey);
  const serverEcdh = await rawPublic(serverPair.publicKey);

  // 2. The server proves who it is by signing what was exchanged.
  const serverKey = await generateKey(info.signature.alg, 'payroll-server-key');
  const transcript = concat(encoder.encode(HANDSHAKE_CONTEXT), browserEcdh, serverEcdh, kemCipherText ?? new Uint8Array());
  const handshakeSignature = await signBytes(serverKey, transcript);
  const handshakeVerified = await verifySignature(serverKey.publicJwk, transcript, handshakeSignature);

  // 3. The login request travels encrypted under a key both sides derived.
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedRequest = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await channelKey(browserSecret), encoder.encode(LOGIN_REQUEST)),
  );
  const decryptedRequest = new TextDecoder().decode(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await channelKey(serverSecret), encryptedRequest as BufferSource),
  );

  // 4. The server signs a login token; later requests are checked against its public key.
  const token = await signJwt(serverKey, tokenClaims());
  const tokenVerified = (await verifyJwt(token, [serverKey.publicJwk], verifyOptions(mode))).ok;

  return {
    mode,
    wire: { browserEcdh, serverEcdh, kemPublicKey, kemCipherText, handshakeSignature, iv, encryptedRequest },
    sharedSecret: { browser: browserSecret, server: serverSecret },
    serverKey,
    handshakeVerified,
    decryptedRequest,
    token,
    tokenVerified,
    held: { serverEcdhPrivate: serverPair.privateKey, browserEcdhPublic: browserPair.publicKey },
  };
}

export interface AttackResult {
  computer: Computer;
  /** Did the attacker end up with the connection's shared secret? */
  recoveredSharedSecret: boolean;
  /** Did the attacker end up with the server's signing key? */
  recoveredSigningKey: boolean;
  /** The recorded login request, if it could be decrypted. */
  readLogin: string | undefined;
  forgedToken: string;
  forgeryAccepted: boolean;
}

/**
 * An attacker who recorded the whole exchange. A quantum computer recovers the
 * private halves of the elliptic-curve keys (modelled by using the ones held
 * above). It gets nothing from ML-KEM or ML-DSA. What follows is real: the
 * decryption either works or throws, and the server's verifier either accepts
 * the forged token or rejects it.
 */
export async function runAttack(session: Session, computer: Computer): Promise<AttackResult> {
  const info = MODES[session.mode];
  const breaksEllipticCurves = computer === 'quantum';

  // The connection: with the ECDH private key the attacker can redo the ECDH
  // step. Without ML-KEM's secret, that is only part of the hybrid secret.
  let readLogin: string | undefined;
  if (breaksEllipticCurves) {
    const partial = await ecdhSecret(session.held.serverEcdhPrivate, session.held.browserEcdhPublic);
    try {
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: session.wire.iv as BufferSource },
        await channelKey(partial),
        session.wire.encryptedRequest as BufferSource,
      );
      readLogin = new TextDecoder().decode(plain);
    } catch {
      readLogin = undefined; // the ML-KEM half of the secret is missing
    }
  }

  // The signature: with the server's signing key the attacker can sign anything.
  const recoveredSigningKey = breaksEllipticCurves && !info.signature.quantumSafe;
  const forgingKey = recoveredSigningKey ? session.serverKey : await generateKey(info.signature.alg, session.serverKey.kid);
  const forgedToken = await signJwt(forgingKey, { ...tokenClaims(), name: 'Alice Nakamura (forged by Mallory)' });
  const forgeryAccepted = (await verifyJwt(forgedToken, [session.serverKey.publicJwk], verifyOptions(session.mode))).ok;

  return { computer, recoveredSharedSecret: readLogin !== undefined, recoveredSigningKey, readLogin, forgedToken, forgeryAccepted };
}

/** The first bytes of a value as hex, for display. These are real values from the run. */
export function hex(bytes: Uint8Array, count = 6): string {
  return [...bytes.slice(0, count)].map((b) => b.toString(16).padStart(2, '0')).join(' ');
}
