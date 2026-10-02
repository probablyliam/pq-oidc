/**
 * The real cryptography behind the login walkthrough. One call runs one
 * login with real primitives, in the browser, and returns every value the
 * stage shows:
 *
 *   key establishment   X25519, and ML-KEM-768 with it in the hybrid modes,
 *                       combined in the order X25519MLKEM768 specifies
 *   key schedule        the TLS 1.3 key schedule: the same functions the
 *                       scanner uses to decrypt real handshakes
 *   server identity     a CertificateVerify signature in the TLS 1.3 format
 *   the login           one TLS 1.3 record, AES-256-GCM under the client's
 *                       application traffic key
 *   the token           a JWT signed by a separate token-signing key
 *
 * What is simplified: the handshake messages are short labelled byte strings
 * rather than TLS wire format, and the certificate is a bare public key with
 * no chain. What is not real at all is the quantum computer: `runAttack`
 * hands the attacker the private values such a machine would compute, and
 * everything she then does with them (deriving keys, decrypting, signing, the
 * server checking her token) actually runs.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { applicationSecrets, certificateVerifyInput, finishedVerifyData, handshakeSecrets, recordNonce, trafficKeys, transcriptHash } from '@pq-oidc/scan-core/keyschedule';
import { generateKey, signBytes, signJwt, verifyJwt, verifySignature } from '../crypto/jws.ts';
import type { LabKey } from '../crypto/jws.ts';

export type Mode = 'classical' | 'hybrid' | 'pq';
export type Attacker = 'none' | 'classical' | 'quantum';

export interface ModeInfo {
  id: Mode;
  label: string;
  /** One line: where this configuration is found. */
  where: string;
  group: string;
  postQuantumKex: boolean;
  signatureAlg: 'ES256' | 'ML-DSA-65';
  signatureName: string;
  postQuantumSignatures: boolean;
}

export const MODES: Record<Mode, ModeInfo> = {
  classical: {
    id: 'classical',
    label: 'Classical',
    where: 'How most logins worked until recently.',
    group: 'X25519',
    postQuantumKex: false,
    signatureAlg: 'ES256',
    signatureName: 'ECDSA P-256',
    postQuantumSignatures: false,
  },
  hybrid: {
    id: 'hybrid',
    label: 'Hybrid key exchange',
    where: 'Where much of the web is now: the key exchange is protected, the signatures are not.',
    group: 'X25519MLKEM768',
    postQuantumKex: true,
    signatureAlg: 'ES256',
    signatureName: 'ECDSA P-256',
    postQuantumSignatures: false,
  },
  pq: {
    id: 'pq',
    label: 'Post-quantum',
    where: 'Key exchange and signatures both replaced. Not available from public certificate authorities yet.',
    group: 'X25519MLKEM768',
    postQuantumKex: true,
    signatureAlg: 'ML-DSA-65',
    signatureName: 'ML-DSA-65',
    postQuantumSignatures: true,
  },
};

/** What the visitor typed into the login form. It never leaves the page. */
export interface Login {
  username: string;
  password: string;
}
export const DEFAULT_LOGIN: Login = { username: 'alice', password: 'hunter2' };
/** As much as a chip on the stage can show. */
export const LOGIN_LIMITS = { username: 8, password: 11 };

/** The request the browser sends: an ordinary form post. */
export const loginRequest = (login: Login) => `POST /login\nusername=${encodeURIComponent(login.username)}&password=${encodeURIComponent(login.password)}`;
export const LOGIN_REQUEST = loginRequest(DEFAULT_LOGIN);

/** Reads the password back out of a request, as the server does after decrypting it, and as an attacker would. */
export function passwordIn(request: string): string {
  return new URLSearchParams(request.split('\n')[1] ?? '').get('password') ?? '';
}

/** Empty fields fall back to the example login; long ones are cut to what the stage can show. */
export function cleanLogin(login: Login): Login {
  return {
    username: login.username.trim().slice(0, LOGIN_LIMITS.username) || DEFAULT_LOGIN.username,
    password: login.password.slice(0, LOGIN_LIMITS.password) || DEFAULT_LOGIN.password,
  };
}
const ISSUER = 'https://payroll.example';
const AUDIENCE = 'payroll';
const HASH = 'sha384'; // TLS_AES_256_GCM_SHA384
const encoder = new TextEncoder();

export interface Session {
  mode: Mode;
  login: Login;
  /** Public values, exactly what crosses the network in the clear. */
  clientShare: Uint8Array;
  serverShare: Uint8Array;
  kemPublicKey?: Uint8Array;
  kemCiphertext?: Uint8Array;
  /** Secrets. Each side computes them; they are never sent. */
  ecdhSecret: Uint8Array;
  kemSecret?: Uint8Array;
  /** What goes into the key schedule: for the hybrid group, the ML-KEM secret then the X25519 secret. */
  sharedSecret: Uint8Array;
  secretsMatch: boolean;
  /** The client's application traffic key, as derived by the browser. */
  channelKey: Uint8Array;
  certKey: LabKey;
  certificateVerify: Uint8Array;
  certificateVerifyValid: boolean;
  finishedValid: boolean;
  /** The login as one TLS record: 5 header bytes, ciphertext, 16-byte tag. */
  loginRecord: Uint8Array;
  loginDecrypted: string;
  tokenKey: LabKey;
  token: string;
  tokenValid: boolean;
  /** Private values kept so the conceptual attack has something to "recover". */
  held: { clientPrivate: Uint8Array; transcript: Uint8Array[] };
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

const message = (label: string, ...parts: Uint8Array[]) => concat(encoder.encode(label), ...parts);
const view = (bytes: Uint8Array) => bytes as Uint8Array<ArrayBuffer>;

async function aesKey(key: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', view(key), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** Protects one record the way TLS 1.3 does (RFC 8446 §5.2): content type appended, header as additional data. */
async function sealRecord(keys: { key: Uint8Array; iv: Uint8Array }, plaintext: Uint8Array): Promise<Uint8Array> {
  const inner = concat(plaintext, Uint8Array.of(0x17));
  const length = inner.length + 16;
  const header = Uint8Array.of(0x17, 0x03, 0x03, length >> 8, length & 0xff);
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: view(recordNonce(keys.iv, 0)), additionalData: view(header) }, await aesKey(keys.key), view(inner));
  return concat(header, new Uint8Array(sealed));
}

/** Returns the plaintext, or undefined if the key is wrong (the tag does not verify). */
async function openRecord(keys: { key: Uint8Array; iv: Uint8Array }, record: Uint8Array): Promise<string | undefined> {
  try {
    const opened = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: view(recordNonce(keys.iv, 0)), additionalData: view(record.subarray(0, 5)) },
      await aesKey(keys.key),
      view(record.subarray(5)),
    );
    return new TextDecoder().decode(new Uint8Array(opened).subarray(0, -1));
  } catch {
    return undefined;
  }
}

/** Everything both sides derive once they have the shared secret and have seen the same messages. */
function schedule(sharedSecret: Uint8Array, hello: Uint8Array[], rest: Uint8Array[]) {
  const handshake = handshakeSecrets(HASH, sharedSecret, transcriptHash(HASH, ...hello));
  return { handshake, application: (finished: Uint8Array) => applicationSecrets(HASH, handshake.handshakeSecret, transcriptHash(HASH, ...hello, ...rest, finished)) };
}

function tokenClaims(login: Login) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: AUDIENCE, sub: login.username, name: login.username, iat: now, exp: now + 3600 };
}

export async function runSession(mode: Mode, login: Login = DEFAULT_LOGIN): Promise<Session> {
  const info = MODES[mode];

  // Key establishment. Each side makes a one-time pair and sends the public half.
  const client = x25519.keygen();
  const server = x25519.keygen();
  const ecdhClient = x25519.getSharedSecret(client.secretKey, server.publicKey);
  const ecdhServer = x25519.getSharedSecret(server.secretKey, client.publicKey);
  let sharedClient: Uint8Array = ecdhClient;
  let sharedServer: Uint8Array = ecdhServer;
  let kem: { publicKey: Uint8Array; cipherText: Uint8Array; secret: Uint8Array } | undefined;
  if (info.postQuantumKex) {
    // ML-KEM: the browser sends a public key, the server encapsulates a secret to it.
    const pair = ml_kem768.keygen();
    const sent = ml_kem768.encapsulate(pair.publicKey);
    const received = ml_kem768.decapsulate(sent.cipherText, pair.secretKey);
    kem = { publicKey: pair.publicKey, cipherText: sent.cipherText, secret: sent.sharedSecret };
    // X25519MLKEM768 puts the ML-KEM secret first.
    sharedClient = concat(received, ecdhClient);
    sharedServer = concat(sent.sharedSecret, ecdhServer);
  }

  const clientHello = message('ClientHello', client.publicKey, kem?.publicKey ?? new Uint8Array());
  const serverHello = message('ServerHello', server.publicKey, kem?.cipherText ?? new Uint8Array());

  // The server proves who it is: it signs the conversation so far with its certificate key.
  const certKey = await generateKey(info.signatureAlg, 'payroll-certificate');
  const certificate = message('Certificate', encoder.encode(JSON.stringify(certKey.publicJwk)));
  const signedInput = certificateVerifyInput(transcriptHash(HASH, clientHello, serverHello, certificate));
  const certificateVerify = await signBytes(certKey, signedInput);
  const certificateVerifyValid = await verifySignature(certKey.publicJwk, signedInput, certificateVerify);
  const verifyMessage = message('CertificateVerify', certificateVerify);

  // Finished: each side shows it derived the same keys from the same transcript.
  const transcript = [certificate, verifyMessage];
  const serverSide = schedule(sharedServer, [clientHello, serverHello], transcript);
  const clientSide = schedule(sharedClient, [clientHello, serverHello], transcript);
  const upToVerify = transcriptHash(HASH, clientHello, serverHello, ...transcript);
  const finished = finishedVerifyData(HASH, serverSide.handshake.serverHandshakeTraffic, upToVerify);
  const expected = finishedVerifyData(HASH, clientSide.handshake.serverHandshakeTraffic, upToVerify);
  const finishedValid = finished.every((byte, i) => byte === expected[i]);
  const finishedMessage = message('Finished', finished);

  // The login travels as application data under the client's traffic key.
  const clientKeys = trafficKeys(HASH, clientSide.application(finishedMessage).clientApplicationTraffic, 32);
  const serverKeys = trafficKeys(HASH, serverSide.application(finishedMessage).clientApplicationTraffic, 32);
  const loginRecord = await sealRecord(clientKeys, encoder.encode(loginRequest(login)));
  const loginDecrypted = (await openRecord(serverKeys, loginRecord)) ?? '';

  // The token is signed by a different key: the application's, not TLS's.
  const tokenKey = await generateKey(info.signatureAlg, 'payroll-tokens');
  const token = await signJwt(tokenKey, tokenClaims(login));
  const tokenValid = (await verifyJwt(token, [tokenKey.publicJwk], { issuer: ISSUER, audience: AUDIENCE, algorithms: [info.signatureAlg] })).ok;

  return {
    mode,
    login,
    clientShare: client.publicKey,
    serverShare: server.publicKey,
    kemPublicKey: kem?.publicKey,
    kemCiphertext: kem?.cipherText,
    ecdhSecret: ecdhClient,
    kemSecret: kem?.secret,
    sharedSecret: sharedClient,
    secretsMatch: sharedClient.every((byte, i) => byte === sharedServer[i]),
    channelKey: clientKeys.key,
    certKey,
    certificateVerify,
    certificateVerifyValid,
    finishedValid,
    loginRecord,
    loginDecrypted,
    tokenKey,
    token,
    tokenValid,
    held: { clientPrivate: client.secretKey, transcript: [clientHello, serverHello, certificate, verifyMessage, finishedMessage] },
  };
}

export interface AttackOutcome {
  attacker: 'classical' | 'quantum';
  /** She obtained the X25519 private half (a quantum computer running Shor's algorithm). */
  recoveredEcdhPrivate: boolean;
  /** She holds the whole shared secret. False when part of it came from ML-KEM. */
  recoveredSharedSecret: boolean;
  /** The recorded login, if her derived key opened it. */
  decryptedLogin: string | undefined;
  recoveredTokenKey: boolean;
  forgedToken: string;
  forgeryAccepted: boolean;
}

/**
 * An attacker who recorded everything that crossed the network. A quantum
 * computer is modelled by giving her the private half of the X25519 share and
 * of any classical signing key. It gives her nothing for ML-KEM or ML-DSA.
 * What follows is real: the decryption either works or fails its tag check,
 * and the verifier either accepts her token or rejects it.
 */
export async function runAttack(session: Session, attacker: 'classical' | 'quantum'): Promise<AttackOutcome> {
  const info = MODES[session.mode];
  const quantum = attacker === 'quantum';

  let decryptedLogin: string | undefined;
  if (quantum) {
    // With the X25519 private half she redoes that part of the key exchange. The ML-KEM part she cannot.
    const ecdh = x25519.getSharedSecret(session.held.clientPrivate, session.serverShare);
    const guess = info.postQuantumKex ? concat(new Uint8Array(32), ecdh) : ecdh;
    const [clientHello, serverHello, certificate, verifyMessage, finishedMessage] = session.held.transcript as [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];
    const derived = schedule(guess, [clientHello, serverHello], [certificate, verifyMessage]).application(finishedMessage);
    decryptedLogin = await openRecord(trafficKeys(HASH, derived.clientApplicationTraffic, 32), session.loginRecord);
  }

  // The token-signing public key is published. Shor's algorithm turns a classical one into the private key.
  const recoveredTokenKey = quantum && !info.postQuantumSignatures;
  const forgingKey = recoveredTokenKey ? session.tokenKey : await generateKey(info.signatureAlg, session.tokenKey.kid);
  const forgedToken = await signJwt(forgingKey, { ...tokenClaims(session.login), name: `${session.login.username} (forged by Mallory)` });
  const forgeryAccepted = (await verifyJwt(forgedToken, [session.tokenKey.publicJwk], { issuer: ISSUER, audience: AUDIENCE, algorithms: [info.signatureAlg] })).ok;

  return {
    attacker,
    recoveredEcdhPrivate: quantum,
    recoveredSharedSecret: quantum && !info.postQuantumKex,
    decryptedLogin,
    recoveredTokenKey,
    forgedToken,
    forgeryAccepted,
  };
}

/** The first bytes of a value as hex, for display. */
export function hex(bytes: Uint8Array, count = 6): string {
  return [...bytes.subarray(0, count)].map((b) => b.toString(16).padStart(2, '0')).join(' ');
}
