/**
 * The Login Lab as explicit events. The visualiser draws whatever the current
 * event says, so replay, pause and step are just moving an index, and the
 * same events can be shown for any mode.
 *
 * Each event carries three levels of explanation:
 *   title   what is happening, in a few words
 *   what    "What just happened?", one or two plain sentences
 *   detail  the technical version, with real values from this run
 * and says how real it is: `real` (an actual cryptographic operation ran),
 * `representative` (a simplified picture of a real protocol step) or
 * `conceptual` (a model of something that can't be done today).
 */
import { hex, MODES } from './crypto.ts';
import type { AttackResult, Computer, Session } from './crypto.ts';

export type Actor = 'browser' | 'server' | 'attacker';
export type Layer = 'request' | 'connection' | 'login';
export type Authenticity = 'real' | 'representative' | 'conceptual';

/** The visual vocabulary. Each kind always looks the same. */
export type ObjectKind =
  | 'data'
  | 'key-share'
  | 'shared-secret'
  | 'private-key'
  | 'public-key'
  | 'signature'
  | 'encrypted'
  | 'token'
  | 'nothing';

export interface Thing {
  kind: ObjectKind;
  label: string;
  /** A short real value (hex) or note shown under the label. */
  value?: string;
  /** Made or held by the attacker. */
  hostile?: boolean;
}

export interface Operation {
  at: Actor;
  verb: 'derive' | 'sign' | 'verify' | 'encrypt' | 'decrypt' | 'check' | 'recover';
  inputs: Thing[];
  output: Thing;
  /** For verify, check and recover: did it work? */
  ok?: boolean;
}

export interface Packet {
  from: Actor;
  to: Actor;
  thing: Thing;
}

export interface LabEvent {
  id: string;
  layer: Layer;
  title: string;
  what: string;
  detail: string;
  authenticity: Authenticity;
  packets?: Packet[];
  operation?: Operation;
  /** Things an actor holds from this event onwards. */
  gains?: Partial<Record<Actor, Thing[]>>;
  /** The connection is encrypted from this event onwards. */
  secures?: boolean;
  outcome?: 'good' | 'bad';
}

const secret = (session: Session, side: 'browser' | 'server'): Thing => ({
  kind: 'shared-secret',
  label: 'Shared secret',
  value: hex(session.sharedSecret[side]),
});

export function loginEvents(session: Session): LabEvent[] {
  const mode = MODES[session.mode];
  const kem = session.wire.kemCipherText !== undefined;
  const privateKey: Thing = { kind: 'private-key', label: 'Server’s private key', value: 'never leaves the server' };
  const publicKey: Thing = { kind: 'public-key', label: 'Server’s public key' };
  const request: Thing = { kind: 'data', label: 'Login request', value: 'alice@example.com, ••••••••' };
  const encrypted: Thing = { kind: 'encrypted', label: 'Encrypted request', value: hex(session.wire.encryptedRequest) };
  const signatureBytes = session.wire.handshakeSignature.length.toLocaleString('en-US');

  return [
    {
      id: 'LOGIN_SUBMITTED',
      layer: 'request',
      title: 'You press Log in',
      what: 'Your browser has your username and password ready to send. It won’t send them until the connection is safe.',
      detail: 'POST /login with a form body. Nothing has left the browser yet.',
      authenticity: 'representative',
      gains: { browser: [request] },
    },
    {
      id: 'KEY_AGREEMENT',
      layer: 'connection',
      title: 'Browser and server agree on a secret',
      what: 'Each side sends the other a public value. From those, both compute the same secret. The secret itself never crosses the network.',
      detail: `${mode.keyAgreement.name} (${mode.keyAgreement.standard}). ${
        kem
          ? `The browser also sends an ML-KEM-768 public key (${session.wire.kemPublicKey?.length.toLocaleString('en-US')} bytes) and the server answers with a ${session.wire.kemCipherText?.length.toLocaleString('en-US')}-byte ciphertext (FIPS 203). `
          : ''
      }Both sides derived ${hex(session.sharedSecret.browser)}…`,
      authenticity: 'real',
      packets: [
        { from: 'browser', to: 'server', thing: { kind: 'key-share', label: kem ? 'Key share + ML-KEM key' : 'Key share', value: hex(session.wire.browserEcdh, 4) } },
        { from: 'server', to: 'browser', thing: { kind: 'key-share', label: kem ? 'Key share + ML-KEM reply' : 'Key share', value: hex(session.wire.serverEcdh, 4) } },
      ],
      gains: { browser: [secret(session, 'browser')], server: [secret(session, 'server')] },
    },
    {
      id: 'SERVER_SIGNS',
      layer: 'connection',
      title: 'The server proves who it is',
      what: 'The server signs the conversation so far with its private key and sends the signature. Only the holder of that key could have made it.',
      detail: `${mode.signature.name} signature over the handshake, ${signatureBytes} bytes (${mode.signature.standard}). In real TLS the public key arrives inside a certificate.`,
      authenticity: 'real',
      operation: {
        at: 'server',
        verb: 'sign',
        inputs: [{ kind: 'data', label: 'The handshake so far' }, privateKey],
        output: { kind: 'signature', label: 'Signature', value: `${signatureBytes} bytes` },
      },
      packets: [{ from: 'server', to: 'browser', thing: { kind: 'signature', label: 'Signature + public key', value: hex(session.wire.handshakeSignature, 4) } }],
      gains: { browser: [publicKey] },
    },
    {
      id: 'SERVER_AUTHENTICATED',
      layer: 'connection',
      title: 'The browser checks the proof',
      what: 'Your browser checks the signature with the server’s public key. It matches, so this really is the Payroll server and not someone in the middle.',
      detail: `${mode.signature.name} verification returned ${session.handshakeVerified}.`,
      authenticity: 'real',
      operation: {
        at: 'browser',
        verb: 'verify',
        inputs: [{ kind: 'signature', label: 'Signature' }, publicKey],
        output: { kind: 'data', label: 'It is the real server' },
        ok: session.handshakeVerified,
      },
    },
    {
      id: 'SECURE_CHANNEL_ESTABLISHED',
      layer: 'connection',
      title: 'The connection is now private',
      what: 'From here on, everything between your browser and the server is encrypted with a key made from the shared secret.',
      detail: 'HKDF-SHA-256 turns the shared secret into an AES-256-GCM key on both sides.',
      authenticity: 'real',
      secures: true,
    },
    {
      id: 'LOGIN_REQUEST_SENT',
      layer: 'request',
      title: 'Your password travels encrypted',
      what: 'The browser encrypts the login request and sends it. Anyone watching the network sees scrambled bytes.',
      detail: `AES-256-GCM. On the wire: ${hex(session.wire.encryptedRequest, 10)}… (${session.wire.encryptedRequest.length} bytes).`,
      authenticity: 'real',
      operation: { at: 'browser', verb: 'encrypt', inputs: [request, secret(session, 'browser')], output: encrypted },
      packets: [{ from: 'browser', to: 'server', thing: encrypted }],
    },
    {
      id: 'SERVER_VERIFIES_REQUEST',
      layer: 'login',
      title: 'The server checks your password',
      what: 'The server decrypts the request with the same secret and checks the password. This part has nothing to do with signatures.',
      detail: 'AES-256-GCM decryption, then a password check (real servers compare against a stored hash).',
      authenticity: 'real',
      operation: {
        at: 'server',
        verb: 'check',
        inputs: [encrypted, secret(session, 'server')],
        output: { kind: 'data', label: 'Password correct' },
        ok: true,
      },
    },
    {
      id: 'SESSION_CREATED',
      layer: 'login',
      title: 'The server signs a login token',
      what: 'So you don’t send your password again, the server writes a token saying “this is Alice” and signs it with its private key.',
      detail: `A JWT signed with ${mode.signature.alg}; ${session.token.length.toLocaleString('en-US')} bytes in total. The token is readable by anyone who holds it: it is signed, not encrypted.`,
      authenticity: 'real',
      operation: {
        at: 'server',
        verb: 'sign',
        inputs: [{ kind: 'data', label: '“This is Alice”' }, privateKey],
        output: { kind: 'token', label: 'Login token', value: `${session.token.length.toLocaleString('en-US')} bytes` },
      },
      packets: [{ from: 'server', to: 'browser', thing: { kind: 'token', label: 'Login token' } }],
      gains: { browser: [{ kind: 'token', label: 'Login token', value: `signed with ${mode.signature.name}` }] },
    },
    {
      id: 'LOGIN_SUCCESS',
      layer: 'login',
      title: 'You are logged in',
      what: 'Your browser shows the app. Every later request carries the token, and the server checks its signature with the public key.',
      detail: `Token verification returned ${session.tokenVerified}.`,
      authenticity: 'real',
      operation: {
        at: 'server',
        verb: 'verify',
        inputs: [{ kind: 'token', label: 'Login token' }, publicKey],
        output: { kind: 'data', label: 'Token is genuine' },
        ok: session.tokenVerified,
      },
      outcome: 'good',
    },
  ];
}

export function attackEvents(session: Session, result: AttackResult): LabEvent[] {
  const mode = MODES[session.mode];
  const quantum = result.computer === 'quantum';
  const machine = quantum ? 'quantum computer' : 'classical computer';
  const kem = session.wire.kemCipherText !== undefined;
  const keyShares: Thing = { kind: 'key-share', label: 'Both key shares', hostile: true };
  const publicKey: Thing = { kind: 'public-key', label: 'Server’s public key', hostile: true };
  const recording: Thing = { kind: 'encrypted', label: 'Recorded login', value: hex(session.wire.encryptedRequest), hostile: true };

  const connectionBarrier = !quantum
    ? 'Working a secret out from the key shares would take a classical computer longer than the age of the universe.'
    : kem
      ? 'The elliptic-curve half falls to a quantum computer. The ML-KEM half is built on a lattice problem with no known quantum shortcut, so the secret stays incomplete.'
      : '';
  const signatureBarrier = !quantum
    ? 'No practical classical attack recovers the private key from the public key at this size.'
    : 'ML-DSA is built on lattice problems believed to be hard for quantum computers too.';

  return [
    {
      id: 'ATTACK_OBSERVES_TRAFFIC',
      layer: 'connection',
      title: 'Mallory records everything on the network',
      what: 'She can’t stop the login, but she keeps a copy of everything that crossed: the key shares, the signature and public key, and the encrypted request.',
      detail: 'A passive network observer. Recording now to attack later is known as “harvest now, decrypt later”.',
      authenticity: 'representative',
      packets: [{ from: 'browser', to: 'attacker', thing: { kind: 'encrypted', label: 'A copy of the traffic', hostile: true } }],
      gains: { attacker: [keyShares, publicKey, recording] },
    },
    {
      id: 'ATTACKER_SEES_PUBLIC_KEY',
      layer: 'connection',
      title: 'What she has, and what she doesn’t',
      what: 'She has every public value. She does not have the shared secret or the server’s private key: neither ever crossed the network.',
      detail: 'The security never depended on hiding public keys. It depends on how hard it is to work the private values out from them.',
      authenticity: 'real',
    },
    {
      id: result.recoveredSharedSecret ? 'KEY_RECOVERY' : quantum ? 'QUANTUM_ATTACK_BARRIER' : 'CLASSICAL_ATTACK_BARRIER',
      layer: 'connection',
      title: result.recoveredSharedSecret ? 'She works out the shared secret' : 'She can’t work out the shared secret',
      what: result.recoveredSharedSecret
        ? 'A large quantum computer can solve the maths behind elliptic-curve key agreement, giving her the same secret the browser and server computed.'
        : connectionBarrier,
      detail: `${quantum ? 'Conceptual future quantum attack' : 'Classical attack'} on ${mode.keyAgreement.name}. ${
        result.recoveredSharedSecret ? 'Shor’s algorithm solves the elliptic-curve discrete-logarithm problem; the page stands in for it by using the private value it already holds.' : ''
      }`,
      authenticity: result.recoveredSharedSecret ? 'conceptual' : 'representative',
      operation: {
        at: 'attacker',
        verb: 'recover',
        inputs: [keyShares, { kind: 'data', label: `Her ${machine}`, hostile: true }],
        output: result.recoveredSharedSecret
          ? { kind: 'shared-secret', label: 'Shared secret', value: hex(session.sharedSecret.server), hostile: true }
          : { kind: 'nothing', label: 'No secret' },
        ok: result.recoveredSharedSecret,
      },
      gains: result.recoveredSharedSecret
        ? { attacker: [{ kind: 'shared-secret', label: 'Shared secret', value: hex(session.sharedSecret.server), hostile: true }] }
        : undefined,
    },
    {
      id: result.readLogin ? 'RECORDED_LOGIN_DECRYPTED' : 'RECORDED_LOGIN_SAFE',
      layer: 'request',
      title: result.readLogin ? 'She reads the recorded login' : 'The recorded login stays unreadable',
      what: result.readLogin
        ? 'With the secret she decrypts what she recorded, even years later, and has Alice’s password.'
        : 'Without the full secret the recording is noise. Decryption fails.',
      detail: result.readLogin
        ? 'AES-256-GCM decryption of the recorded bytes succeeded with the recovered key. This step is real.'
        : 'AES-256-GCM rejects the wrong key outright. This step is real.',
      authenticity: 'real',
      operation: {
        at: 'attacker',
        verb: 'decrypt',
        inputs: [recording],
        output: result.readLogin
          ? { kind: 'data', label: 'Alice’s username and password', hostile: true }
          : { kind: 'nothing', label: 'Unreadable' },
        ok: result.readLogin !== undefined,
      },
      outcome: result.readLogin ? 'bad' : 'good',
    },
    {
      id: result.recoveredSigningKey ? 'SIGNING_KEY_RECOVERY' : 'SIGNING_KEY_BARRIER',
      layer: 'login',
      title: result.recoveredSigningKey ? 'She works out the server’s private key' : 'She can’t work out the private key',
      what: result.recoveredSigningKey
        ? 'The same quantum attack turns the server’s public key into its private key. The server was never touched.'
        : signatureBarrier,
      detail: `${quantum ? 'Conceptual future quantum attack' : 'Classical attack'} on ${mode.signature.name} (${mode.signature.standard}).`,
      authenticity: result.recoveredSigningKey ? 'conceptual' : 'representative',
      operation: {
        at: 'attacker',
        verb: 'recover',
        inputs: [publicKey, { kind: 'data', label: `Her ${machine}`, hostile: true }],
        output: result.recoveredSigningKey
          ? { kind: 'private-key', label: 'Server’s private key', hostile: true }
          : { kind: 'nothing', label: 'No private key' },
        ok: result.recoveredSigningKey,
      },
      gains: result.recoveredSigningKey ? { attacker: [{ kind: 'private-key', label: 'Server’s private key', hostile: true }] } : undefined,
    },
    {
      id: 'SIGNATURE_FORGERY',
      layer: 'login',
      title: 'She signs her own login token',
      what: result.recoveredSigningKey
        ? 'With the real private key she writes a token saying she is Alice. Its signature is indistinguishable from a genuine one.'
        : 'Without the private key she signs a token with a key she made up, and sends it anyway.',
      detail: `A JWT signed with ${mode.signature.alg}, using ${result.recoveredSigningKey ? 'the recovered key' : 'an unrelated key'}. Signing is real.`,
      authenticity: 'real',
      operation: {
        at: 'attacker',
        verb: 'sign',
        inputs: [
          { kind: 'data', label: '“This is Alice”', hostile: true },
          { kind: 'private-key', label: result.recoveredSigningKey ? 'Server’s private key' : 'A made-up key', hostile: true },
        ],
        output: { kind: 'token', label: 'Forged token', hostile: true },
      },
      packets: [{ from: 'attacker', to: 'server', thing: { kind: 'token', label: 'Forged token', hostile: true } }],
    },
    {
      id: result.forgeryAccepted ? 'SERVER_ACCEPTS' : 'SERVER_REJECTS',
      layer: 'login',
      title: result.forgeryAccepted ? 'The server accepts it. She is in as Alice.' : 'The server rejects it',
      what: result.forgeryAccepted
        ? 'The signature checks out against the public key, so the server has no way to tell. No password was needed.'
        : 'The signature doesn’t match the server’s public key. Access denied.',
      detail: `Real ${mode.signature.name} verification returned ${result.forgeryAccepted}.`,
      authenticity: 'real',
      operation: {
        at: 'server',
        verb: 'verify',
        inputs: [{ kind: 'token', label: 'Forged token', hostile: true }, { kind: 'public-key', label: 'Server’s public key' }],
        output: { kind: 'data', label: result.forgeryAccepted ? 'Accepted as Alice' : 'Rejected', hostile: result.forgeryAccepted },
        ok: result.forgeryAccepted,
      },
      outcome: result.forgeryAccepted ? 'bad' : 'good',
    },
  ];
}

/** What each actor holds once the first `count` events have happened. */
export function holdings(events: LabEvent[], count: number, initial: Partial<Record<Actor, Thing[]>> = {}): Record<Actor, Thing[]> {
  const held: Record<Actor, Thing[]> = {
    browser: [...(initial.browser ?? [])],
    server: [...(initial.server ?? [])],
    attacker: [...(initial.attacker ?? [])],
  };
  for (const event of events.slice(0, count)) {
    for (const actor of ['browser', 'server', 'attacker'] as const) {
      for (const thing of event.gains?.[actor] ?? []) {
        if (!held[actor].some((t) => t.kind === thing.kind && t.label === thing.label)) held[actor].push(thing);
      }
    }
  }
  return held;
}

export type { Computer };
