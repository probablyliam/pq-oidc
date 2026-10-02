/**
 * The real cryptography behind the login lab. One call runs one login with
 * real primitives, in the browser, and returns every value the lab shows:
 *
 *   key establishment   X25519, or X25519 with ML-KEM-768 (the hybrid group
 *                       X25519MLKEM768, secrets combined in the order it specifies)
 *   key schedule        the TLS 1.3 key schedule: the same functions the
 *                       scanner uses to decrypt real handshakes
 *   server identity     a CertificateVerify signature in the TLS 1.3 format,
 *                       ECDSA P-256 or ML-DSA-65
 *   the login           one TLS 1.3 record, AES-256-GCM under the client's
 *                       application traffic key
 *   the token           a JWT signed by a separate token-signing key,
 *                       ES256 or ML-DSA-65
 *
 * Each of the three public-key choices is made separately, as a real site
 * can. What is simplified: the handshake messages are short labelled byte
 * strings rather than TLS wire format, and the certificate is a bare public
 * key with no chain. What is not real at all is the quantum computer:
 * `runAttack` hands the attacker the private values such a machine would
 * compute, and everything she then does with them (deriving keys, decrypting,
 * signing, the browser and the server checking her work) actually runs.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { applicationSecrets, certificateVerifyInput, finishedVerifyData, handshakeSecrets, recordNonce, trafficKeys, transcriptHash } from '@pq-oidc/scan-core/keyschedule';
import { base64urlToBytes } from '@pq-oidc/token-kit/base64url';
import { generateKey, signBytes, signJwt, verifyJwt, verifySignature } from '../crypto/jws.ts';
import type { LabKey } from '../crypto/jws.ts';

export type Kex = 'x25519' | 'hybrid';
export type Sig = 'ecdsa' | 'mldsa';
/** What the site uses for each of its three public-key jobs. */
export interface Setup {
  kex: Kex;
  cert: Sig;
  token: Sig;
}
export type Computer = 'ordinary' | 'quantum';

export const DEFAULT_SETUP: Setup = { kex: 'x25519', cert: 'ecdsa', token: 'ecdsa' };

export const KEX: Record<Kex, { name: string; pq: boolean }> = {
  x25519: { name: 'X25519', pq: false },
  hybrid: { name: 'X25519 + ML-KEM-768', pq: true },
};
export const SIG: Record<Sig, { name: string; alg: 'ES256' | 'ML-DSA-65'; pq: boolean }> = {
  ecdsa: { name: 'ECDSA P-256', alg: 'ES256', pq: false },
  mldsa: { name: 'ML-DSA-65', alg: 'ML-DSA-65', pq: true },
};

/** What the visitor typed into the login form. It never leaves the page. */
export interface Login {
  username: string;
  password: string;
}
export const DEFAULT_LOGIN: Login = { username: 'alice', password: 'hunter2' };
/** As much as the lab can show. */
export const LOGIN_LIMITS = { username: 12, password: 16 };

/** The request the browser sends: an ordinary form post. */
export const loginRequest = (login: Login) => `POST /login\nusername=${encodeURIComponent(login.username)}&password=${encodeURIComponent(login.password)}`;

/** Reads the password back out of a request, as the server does after decrypting it, and as an attacker would. */
export function passwordIn(request: string): string {
  return new URLSearchParams(request.split('\n')[1] ?? '').get('password') ?? '';
}

/** Empty fields fall back to the example login; long ones are cut to what the lab can show. */
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
  setup: Setup;
  login: Login;
  /** Public values, exactly what crosses the network in the clear. */
  clientShare: Uint8Array;
  serverShare: Uint8Array;
  kemPublicKey?: Uint8Array;
  kemCiphertext?: Uint8Array;
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
  /** Private values, kept so the lab can show what a quantum computer would recover. Never shown otherwise. */
  held: {
    client: { secretKey: Uint8Array; publicKey: Uint8Array };
    server: { secretKey: Uint8Array; publicKey: Uint8Array };
    certPrivate: Uint8Array;
    tokenPrivate: Uint8Array;
    transcript: Uint8Array[];
  };
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

/** The private value behind a signing key, as bytes: what a quantum computer would hand back. */
async function privateBytes(key: LabKey): Promise<Uint8Array> {
  if ('seed' in key) return key.seed;
  const jwk = await crypto.subtle.exportKey('jwk', key.privateKey);
  return base64urlToBytes(jwk.d ?? '');
}

/**
 * Runs one login. `previous` lets a change to one choice keep the keys of the others, so
 * what the lab shows for a step that did not change stays the same.
 */
export async function runSession(setup: Setup, login: Login = DEFAULT_LOGIN, previous?: Session): Promise<Session> {
  // Key establishment. Each side makes a one-time pair and sends the public half.
  const client = previous?.held.client ?? x25519.keygen();
  const server = previous?.held.server ?? x25519.keygen();
  const ecdhClient = x25519.getSharedSecret(client.secretKey, server.publicKey);
  const ecdhServer = x25519.getSharedSecret(server.secretKey, client.publicKey);
  let sharedClient: Uint8Array = ecdhClient;
  let sharedServer: Uint8Array = ecdhServer;
  let kem: { publicKey: Uint8Array; cipherText: Uint8Array } | undefined;
  if (setup.kex === 'hybrid') {
    // ML-KEM: the browser sends a public key, the server encapsulates a secret to it.
    const pair = ml_kem768.keygen();
    const sent = ml_kem768.encapsulate(pair.publicKey);
    const received = ml_kem768.decapsulate(sent.cipherText, pair.secretKey);
    kem = { publicKey: pair.publicKey, cipherText: sent.cipherText };
    // X25519MLKEM768 puts the ML-KEM secret first.
    sharedClient = concat(received, ecdhClient);
    sharedServer = concat(sent.sharedSecret, ecdhServer);
  }

  const clientHello = message('ClientHello', client.publicKey, kem?.publicKey ?? new Uint8Array());
  const serverHello = message('ServerHello', server.publicKey, kem?.cipherText ?? new Uint8Array());

  // The server proves who it is: it signs the conversation so far with its certificate key.
  const certKey = previous && previous.setup.cert === setup.cert ? previous.certKey : await generateKey(SIG[setup.cert].alg, 'payroll-certificate');
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
  const tokenKey = previous && previous.setup.token === setup.token ? previous.tokenKey : await generateKey(SIG[setup.token].alg, 'payroll-tokens');
  const token = await signJwt(tokenKey, tokenClaims(login));
  const tokenValid = (await verifyJwt(token, [tokenKey.publicJwk], { issuer: ISSUER, audience: AUDIENCE, algorithms: [tokenKey.alg] })).ok;

  return {
    setup,
    login,
    clientShare: client.publicKey,
    serverShare: server.publicKey,
    kemPublicKey: kem?.publicKey,
    kemCiphertext: kem?.cipherText,
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
    held: {
      client,
      server,
      certPrivate: await privateBytes(certKey),
      tokenPrivate: await privateBytes(tokenKey),
      transcript: [clientHello, serverHello, certificate, verifyMessage, finishedMessage],
    },
  };
}

/** What an attacker with a given computer gets out of a recording of one login. */
export interface Attack {
  computer: Computer;
  /** Step 1: the key exchange. A quantum computer recovers the X25519 private half; nothing recovers an ML-KEM one. */
  key: { ecdhRecovered: boolean; kemRecovered: false; decryptedLogin?: string };
  /** Step 2: posing as the site, with a signature the browser checks against the real certificate. */
  site: { keyRecovered: boolean; accepted: boolean };
  /** Step 4: a token of her own, checked by the site with its real public key. */
  token: { keyRecovered: boolean; forged: string; accepted: boolean };
}

/**
 * An attacker who recorded everything that crossed the network. A quantum
 * computer is modelled by giving her the private half of the X25519 share and
 * of any classical signing key. It gives her nothing for ML-KEM or ML-DSA.
 * What follows is real: the decryption either works or fails its tag check,
 * and the browser and the site either accept her signatures or reject them.
 */
export async function runAttack(session: Session, computer: Computer): Promise<Attack> {
  const quantum = computer === 'quantum';
  const hybrid = session.setup.kex === 'hybrid';
  const [clientHello, serverHello, certificate, verifyMessage, finishedMessage] = session.held.transcript as [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];

  // The recording. With the X25519 private half she redoes that part of the key exchange; the ML-KEM part she cannot,
  // and without any private half she has nothing better than a guess.
  const ecdh = quantum ? x25519.getSharedSecret(session.held.client.secretKey, session.serverShare) : new Uint8Array(32);
  const guess = hybrid ? concat(new Uint8Array(32), ecdh) : ecdh;
  const derived = schedule(guess, [clientHello, serverHello], [certificate, verifyMessage]).application(finishedMessage);
  const decryptedLogin = await openRecord(trafficKeys(HASH, derived.clientApplicationTraffic, 32), session.loginRecord);

  // Posing as the site: she answers a fresh visitor's handshake and signs it, as the real site would.
  const certRecovered = quantum && session.setup.cert === 'ecdsa';
  const siteKey = certRecovered ? session.certKey : await generateKey(SIG[session.setup.cert].alg, 'payroll-certificate');
  const visitor = message('ClientHello', crypto.getRandomValues(new Uint8Array(32)));
  const herHello = message('ServerHello', crypto.getRandomValues(new Uint8Array(32)));
  const herInput = certificateVerifyInput(transcriptHash(HASH, visitor, herHello, certificate));
  const siteAccepted = await verifySignature(session.certKey.publicJwk, herInput, await signBytes(siteKey, herInput));

  // A token of her own. The token-signing public key is published; Shor's algorithm turns a classical one into the private key.
  const tokenRecovered = quantum && session.setup.token === 'ecdsa';
  const forgingKey = tokenRecovered ? session.tokenKey : await generateKey(SIG[session.setup.token].alg, session.tokenKey.kid);
  const forged = await signJwt(forgingKey, tokenClaims(session.login));
  const tokenAccepted = (await verifyJwt(forged, [session.tokenKey.publicJwk], { issuer: ISSUER, audience: AUDIENCE, algorithms: [session.tokenKey.alg] })).ok;

  return {
    computer,
    key: { ecdhRecovered: quantum, kemRecovered: false, decryptedLogin },
    site: { keyRecovered: certRecovered, accepted: siteAccepted },
    token: { keyRecovered: tokenRecovered, forged, accepted: tokenAccepted },
  };
}

/** The first bytes of a value as hex, for display. */
export function hex(bytes: Uint8Array, count = 6): string {
  return [...bytes.subarray(0, count)].map((b) => b.toString(16).padStart(2, '0')).join(' ');
}
