/**
 * The score for one login, and for the attack on it.
 *
 * The scenario, with its layers kept apart:
 *   1. Alice submits a login form.                                (application)
 *   2. A TLS 1.3 handshake: key establishment, then the server
 *      proves its identity with a certificate and a signature.    (TLS)
 *   3. The login travels through the channel.                     (application over TLS)
 *   4. The server checks the password and issues a signed token,
 *      using a different key from the certificate's.              (application)
 *   5. The browser uses the token; the server verifies it.        (application)
 *
 * With an attacker, she taps the wire for the whole login and the timeline
 * continues into what she can do with her recording.
 *
 * The score only arranges things in time. Every value it shows comes from the
 * session that actually ran (session.ts).
 */
import type { Action, Beat, Landmark, Prop, Score } from './engine.ts';
import { hex, MODES } from './session.ts';
import type { AttackOutcome, Session } from './session.ts';

export type Actor = 'b' | 's' | 'm';

/** A beat as authored: a length in seconds instead of start and end times. */
interface BeatSpec extends Omit<Beat, 'start' | 'end'> {
  seconds: number;
  landmark?: { id: string; label: string };
  /** The operation chambers that are working during this beat. */
  ops?: StageOp[];
  mark?: StageMark;
}

export interface StageOp {
  actor: Actor;
  label: string;
  /** When in the beat the chamber is working. */
  span: [number, number];
  /** Shown once the work is done. */
  result?: { ok: boolean; text: string };
}

export interface LoginBeat extends Beat {
  ops?: StageOp[];
  mark?: StageMark;
}

export interface LoginScore extends Score {
  beats: LoginBeat[];
}

/** How literally a beat should be taken. Shown next to its caption. */
export type StageMark = 'model' | 'real' | 'simulation';
const SIMPLIFIED = { mark: 'model', honesty: 'The handshake is simplified. The values are real, computed in your browser.' } as const;
const REAL = { mark: 'real', honesty: 'This step really ran in your browser, on the values shown.' } as const;
const CONCEPTUAL = { mark: 'simulation', honesty: 'No computer can do this today. The page hands her what such a machine would compute.' } as const;
const HARDNESS = { mark: 'simulation', honesty: 'An attack that is believed to be infeasible, shown failing.' } as const;

// ---- small helpers for writing actions
const move = (prop: string, to: string, span: [number, number]): Action => ({ prop, move: to, span });
const appear = (prop: string, at: string, span: [number, number]): Action => ({ prop, place: at, show: true, span });
const vanish = (prop: string, span: [number, number]): Action => ({ prop, show: false, span });
const set = (prop: string, values: Record<string, number>, span: [number, number]): Action => ({ prop, set: values, span });
const inOrder = (actions: Action[]) => actions.map((action, i) => ({ action, i })).sort((a, b) => (a.action.span?.[0] ?? 0) - (b.action.span?.[0] ?? 0) || a.i - b.i).map((x) => x.action);

interface OperateOptions {
  /**
   * Props the operation uses, and where each goes afterwards. One that comes back (a key) docks
   * beside the chamber; one that is used up, or is itself transformed (`changes`), goes inside.
   */
  inputs: { prop: string; back?: string; changes?: boolean }[];
  /** What comes out, and where it ends up. */
  output?: { prop: string; to: string };
}

/**
 * Inputs travel to the chamber; the output forms inside it while they are
 * there; then inputs return (or are used up) and the output leaves.
 */
function operate(actor: Actor, { inputs, output }: OperateOptions): Action[] {
  const actions: Action[] = [];
  inputs.forEach(({ prop, back, changes }, i) => {
    actions.push(move(prop, `${actor}.op${i === 0 ? 'A' : 'B'}`, [0, 0.22]));
    if (!back || changes) actions.push(move(prop, `${actor}.op`, [0.24, 0.36]));
    actions.push(back ? move(prop, back, [0.76, 1]) : vanish(prop, [0.36, 0.5]));
  });
  if (output) actions.push(appear(output.prop, `${actor}.op`, [0.38, 0.5]), set(output.prop, { formed: 1 }, [0.38, 0.74]), move(output.prop, output.to, [0.78, 1]));
  return inOrder(actions);
}
const OPERATE_SPAN: [number, number] = [0.24, 0.76];

export function buildScore(session: Session, attack?: AttackOutcome): LoginScore {
  const mode = MODES[session.mode];
  const kem = mode.postQuantumKex;
  const pqSig = mode.postQuantumSignatures;
  const tapped = attack !== undefined;
  const sigBytes = session.certificateVerify.length.toLocaleString('en-US');
  const tokenBytes = session.token.length.toLocaleString('en-US');

  const props: Prop[] = [
    { id: 'screen', kind: 'screen', label: 'payroll.example', home: 'b.screen', visible: true, channels: { typed: 0, pressed: 0, waiting: 0, welcome: 0 } },
    { id: 'wire', kind: 'wire', label: 'Network', home: 'wire', visible: true, channels: { sealed: 0, tunnel: 0 } },
    { id: 'trust', kind: 'trust', label: 'Authorities this browser trusts', home: 'b.trust', visible: true, channels: { checked: 0 } },
    { id: 'certKey', kind: 'key', label: 'Certificate private key', look: { hue: 'cert', solid: true, lattice: pqSig, note: mode.signatureName }, home: 's.slot1', visible: true },
    { id: 'cert', kind: 'cert', label: 'Certificate', look: { hue: 'cert', lattice: pqSig, note: 'key + CA signature' }, home: 's.slot2', visible: true },
    { id: 'tokenKey', kind: 'key', label: 'Token-signing private key', look: { hue: 'token', solid: true, lattice: pqSig, note: mode.signatureAlg }, home: 's.slot3', visible: true },
    { id: 'pwStore', kind: 'data', label: 'Stored password hash', look: { note: 'alice: $argon2id$…' }, home: 's.slot9', visible: true },

    { id: 'cred', kind: 'data', label: 'Login', look: { plain: 'username=alice&password=correct-horse', cipher: hex(session.loginRecord.subarray(5), 18) }, channels: { cipher: 0 } },
    { id: 'cPriv', kind: 'key', label: 'Browser’s private half', look: { hue: 'session', solid: true, note: 'never sent' } },
    { id: 'cPub', kind: 'key', label: 'Browser’s public half', look: { hue: 'session', note: hex(session.clientShare, 5) } },
    { id: 'sPriv', kind: 'key', label: 'Server’s private half', look: { hue: 'session', solid: true, note: 'never sent' } },
    { id: 'sPub', kind: 'key', label: 'Server’s public half', look: { hue: 'session', note: hex(session.serverShare, 5) } },
    { id: 'ecdhC', kind: 'secret', label: kem ? 'X25519 secret' : 'Shared secret', look: { note: hex(session.ecdhSecret, 5) }, channels: { formed: 0 } },
    { id: 'ecdhS', kind: 'secret', label: kem ? 'X25519 secret' : 'Shared secret', look: { note: hex(session.ecdhSecret, 5) }, channels: { formed: 0 } },
    { id: 'keyC', kind: 'key', label: 'Channel key', look: { hue: 'secret', solid: true, note: hex(session.channelKey, 5) }, channels: { formed: 0 } },
    { id: 'keyS', kind: 'key', label: 'Channel key', look: { hue: 'secret', solid: true, note: hex(session.channelKey, 5) }, channels: { formed: 0 } },
    { id: 'said', kind: 'data', label: 'Everything said so far', look: { note: 'both hellos + certificate' } },
    { id: 'cvSig', kind: 'signature', label: 'Signature', look: { hue: 'cert', lattice: pqSig, note: `${sigBytes} bytes` }, channels: { formed: 0 } },
    { id: 'certSent', kind: 'cert', label: 'Certificate', look: { hue: 'cert', lattice: pqSig, note: 'key + CA signature' } },
    { id: 'saidC', kind: 'data', label: 'Everything said so far', look: { note: 'the browser’s own record' } },
    { id: 'claims', kind: 'data', label: 'Claims', look: { note: 'sub: alice, exp: +1 h' } },
    { id: 'token', kind: 'token', label: 'Token', look: { lattice: pqSig, note: `${tokenBytes} bytes, ${mode.signatureAlg}` }, channels: { formed: 0 } },
    { id: 'tokenPub', kind: 'key', label: 'Token public key', look: { hue: 'token', lattice: pqSig, note: 'published for every app' } },
  ];
  if (kem) {
    props.push(
      { id: 'cKemPriv', kind: 'key', label: 'ML-KEM private key', look: { hue: 'session', solid: true, lattice: true, note: 'never sent' } },
      { id: 'cKemPub', kind: 'key', label: 'ML-KEM public key', look: { hue: 'session', lattice: true, note: `${session.kemPublicKey!.length.toLocaleString('en-US')} bytes` } },
      { id: 'kemCt', kind: 'sealed', label: 'ML-KEM ciphertext', look: { hue: 'session', lattice: true, note: `${session.kemCiphertext!.length.toLocaleString('en-US')} bytes` }, channels: { formed: 0 } },
      { id: 'kemC', kind: 'secret', label: 'ML-KEM secret', look: { lattice: true, note: hex(session.kemSecret!, 5) }, channels: { formed: 0 } },
      { id: 'kemS', kind: 'secret', label: 'ML-KEM secret', look: { lattice: true, note: hex(session.kemSecret!, 5) }, channels: { formed: 0 } },
      { id: 'secretC', kind: 'secret', label: 'Shared secret', look: { lattice: 'half', note: hex(session.sharedSecret, 5) }, channels: { formed: 0 } },
      { id: 'secretS', kind: 'secret', label: 'Shared secret', look: { lattice: 'half', note: hex(session.sharedSecret, 5) }, channels: { formed: 0 } },
    );
  }
  if (tapped) {
    props.push(
      { id: 'mallory', kind: 'attacker', label: 'Mallory', home: 'm.self', visible: true },
      { id: 'mCPub', kind: 'key', label: 'Browser’s public half', look: { hue: 'session', hostile: true, note: hex(session.clientShare, 5) } },
      { id: 'mSPub', kind: 'key', label: 'Server’s public half', look: { hue: 'session', hostile: true, note: hex(session.serverShare, 5) } },
      { id: 'mFlight', kind: 'sealed', label: 'Encrypted handshake', look: { hostile: true, note: 'unreadable' }, channels: { formed: 1 } },
      { id: 'mLogin', kind: 'data', label: 'Recorded login', look: { hostile: true, plain: session.loginDecrypted.split('\n')[1] ?? '', cipher: hex(session.loginRecord.subarray(5), 18) }, channels: { cipher: 1 } },
      { id: 'mPriv', kind: 'key', label: 'Browser’s private half', look: { hue: 'session', solid: true, hostile: true, note: 'recovered' }, channels: { formed: 0 } },
      { id: 'mSecret', kind: 'secret', label: kem ? 'Half a secret' : 'Shared secret', look: { hostile: true, note: kem ? 'the ML-KEM half is missing' : hex(session.sharedSecret, 5) }, channels: { formed: 0 } },
      { id: 'mTokenPub', kind: 'key', label: 'Token public key', look: { hue: 'token', lattice: pqSig, hostile: true, note: 'it is public' } },
      { id: 'mTokenKey', kind: 'key', label: attack.recoveredTokenKey ? 'Token-signing private key' : 'A key she made up', look: { hue: 'token', solid: true, hostile: true, lattice: pqSig, note: attack.recoveredTokenKey ? 'recovered' : 'not the server’s' }, channels: { formed: 0 } },
      { id: 'mToken', kind: 'token', label: 'Forged token', look: { hostile: true, lattice: pqSig, note: 'says: I am Alice' }, channels: { formed: 0 } },
    );
    if (kem) {
      props.push(
        { id: 'mKemPub', kind: 'key', label: 'ML-KEM public key', look: { hue: 'session', lattice: true, hostile: true, note: 'public' } },
        { id: 'mKemCt', kind: 'sealed', label: 'ML-KEM ciphertext', look: { hue: 'session', lattice: true, hostile: true, note: 'public' }, channels: { formed: 1 } },
      );
    }
  }

  const specs: BeatSpec[] = [];
  const beat = (spec: BeatSpec) => specs.push({ ...spec, actions: inOrder(spec.actions) });
  /** A copy of something that crossed the wire lands in the attacker's recording. */
  const record = (copy: string, lane: 'tls' | 'app', slot: string, at: number): Action[] => (tapped ? [appear(copy, `tap.${lane}`, [at, at + 0.08]), move(copy, slot, [at + 0.1, at + 0.5])] : []);

  // ------------------------------------------------------------------ Login
  beat({
    id: 'type',
    seconds: 5,
    layer: 'application',
    landmark: { id: 'login', label: 'Login' },
    caption: 'Alice types her password and presses Log in.',
    detail: 'An ordinary form on payroll.example. Nothing has left the browser.',
    ...SIMPLIFIED,
    actions: [set('screen', { typed: 1 }, [0.05, 0.7]), set('screen', { pressed: 1 }, [0.8, 0.95])],
  });
  beat({
    id: 'hold',
    seconds: 5,
    layer: 'application',
    caption: 'The browser has the login ready, and holds on to it. Nothing sensitive goes out until there is a private channel to send it through.',
    detail: 'POST /login, with the username and password in the body.',
    ...SIMPLIFIED,
    actions: [set('screen', { waiting: 1 }, [0, 0.3]), appear('cred', 'b.screen', [0.1, 0.3]), move('cred', 'b.hold', [0.35, 0.9])],
  });

  // ------------------------------------------------------------------ Key establishment
  beat({
    id: 'client-keys',
    seconds: 7,
    layer: 'tls',
    landmark: { id: 'key-establishment', label: 'Key establishment' },
    caption: kem
      ? 'First, the browser makes two one-time key pairs of different kinds. It keeps the private half of each and will send the public halves.'
      : 'First, the browser makes a one-time key pair. It keeps the private half and will send the public half.',
    detail: kem ? 'An X25519 pair and an ML-KEM-768 pair: the hybrid group X25519MLKEM768.' : 'An X25519 key pair, used for this connection only.',
    ...SIMPLIFIED,
    ops: [{ actor: 'b', label: 'Generate keys', span: [0.05, 0.5] }],
    actions: [
      appear('cPriv', 'b.op', [0.1, 0.3]),
      appear('cPub', 'b.op', [0.1, 0.3]),
      move('cPriv', 'b.slot1', [0.45, 0.8]),
      move('cPub', 'b.tls', [0.45, 0.9]),
      ...(kem ? [appear('cKemPriv', 'b.op', [0.2, 0.4]), appear('cKemPub', 'b.op', [0.2, 0.4]), move('cKemPriv', 'b.slot2', [0.5, 0.85]), move('cKemPub', 'b.tls2', [0.5, 0.95])] : []),
    ],
  });
  beat({
    id: 'client-hello',
    seconds: 7,
    layer: 'tls',
    caption: kem ? 'The public halves cross the network in the open. Anyone on the path can copy them.' : 'The public half crosses the network in the open. Anyone on the path can copy it.',
    detail: 'The ClientHello. It is not encrypted: there is no key to encrypt it with yet.',
    ...SIMPLIFIED,
    actions: [
      move('cPub', 's.tls', [0, 0.75]),
      move('cPub', 's.slot5', [0.78, 1]),
      ...(kem ? [move('cKemPub', 's.tls2', [0.05, 0.8]), move('cKemPub', 's.slot6', [0.82, 1])] : []),
      ...record('mCPub', 'tls', 'm.slot1', 0.34),
      ...(kem ? record('mKemPub', 'tls', 'm.slot2', 0.4) : []),
    ],
  });
  beat({
    id: 'server-keys',
    seconds: 7,
    layer: 'tls',
    caption: kem
      ? 'The server makes its own one-time pair. For the ML-KEM part it does something different: it locks a fresh secret inside a box only the browser’s ML-KEM private key can open.'
      : 'The server makes its own one-time pair.',
    detail: kem ? 'ML-KEM encapsulation: the server gets a 32-byte secret and a ciphertext to send back.' : 'Another X25519 pair.',
    ...SIMPLIFIED,
    ops: [{ actor: 's', label: kem ? 'Generate + encapsulate' : 'Generate keys', span: [0.05, 0.6] }],
    actions: [
      appear('sPriv', 's.op', [0.05, 0.2]),
      appear('sPub', 's.op', [0.05, 0.2]),
      move('sPriv', 's.slot4', [0.3, 0.55]),
      move('sPub', 's.tls', [0.6, 0.95]),
      ...(kem
        ? [
            move('cKemPub', 's.op', [0.22, 0.4]),
            appear('kemCt', 's.op', [0.4, 0.5]),
            appear('kemS', 's.op', [0.4, 0.5]),
            set('kemCt', { formed: 1 }, [0.4, 0.6]),
            set('kemS', { formed: 1 }, [0.4, 0.6]),
            vanish('cKemPub', [0.45, 0.6]),
            move('kemS', 's.slot6', [0.64, 0.9]),
            move('kemCt', 's.tls2', [0.64, 0.98]),
          ]
        : []),
    ],
  });
  beat({
    id: 'server-hello',
    seconds: 7,
    layer: 'tls',
    caption: kem ? 'It sends its public half and the locked box back, also in the open.' : 'It sends its public half back, also in the open.',
    detail: 'The ServerHello. From here on, the rest of the handshake is encrypted.',
    ...SIMPLIFIED,
    actions: [
      move('sPub', 'b.tls', [0, 0.75]),
      move('sPub', 'b.slot3', [0.78, 1]),
      ...(kem ? [move('kemCt', 'b.tls2', [0.05, 0.8]), move('kemCt', 'b.slot6', [0.82, 1])] : []),
      ...record('mSPub', 'tls', kem ? 'm.slot3' : 'm.slot2', 0.34),
      ...(kem ? record('mKemCt', 'tls', 'm.slot4', 0.4) : []),
    ],
  });
  beat({
    id: 'combine',
    seconds: 9,
    layer: 'tls',
    caption: 'Each side combines its own private half with the other’s public half. Both arrive at the same secret, and the secret itself never crossed the network.',
    detail: `X25519 on both sides gave ${hex(session.ecdhSecret)}…${kem ? ' The browser also opens the box with its ML-KEM private key.' : ''}`,
    ...SIMPLIFIED,
    ops: [
      { actor: 'b', label: 'Combine', span: OPERATE_SPAN, result: { ok: session.secretsMatch, text: 'Same secret on both sides' } },
      { actor: 's', label: 'Combine', span: OPERATE_SPAN },
    ],
    actions: [
      ...operate('b', { inputs: [{ prop: 'cPriv', back: 'b.slot1' }, { prop: 'sPub' }], output: { prop: 'ecdhC', to: 'b.slot4' } }),
      ...operate('s', { inputs: [{ prop: 'sPriv', back: 's.slot4' }, { prop: 'cPub' }], output: { prop: 'ecdhS', to: 's.slot7' } }),
    ],
  });
  if (kem) {
    beat({
      id: 'decapsulate',
      seconds: 8,
      layer: 'tls',
      caption: 'The browser opens the box and gets the second secret. The two are joined: an attacker would need both to have anything.',
      detail: `ML-KEM decapsulation, then the two secrets concatenated: ${hex(session.sharedSecret)}…`,
      ...SIMPLIFIED,
      ops: [
        { actor: 'b', label: 'Open + join', span: [0.2, 0.8] },
        { actor: 's', label: 'Join', span: [0.64, 0.8] },
      ],
      actions: [
        move('cKemPriv', 'b.opA', [0, 0.18]),
        move('kemCt', 'b.opB', [0, 0.18]),
        move('cKemPriv', 'b.op', [0.2, 0.3]),
        move('kemCt', 'b.op', [0.2, 0.3]),
        vanish('kemCt', [0.32, 0.42]),
        appear('kemC', 'b.op', [0.32, 0.42]),
        set('kemC', { formed: 1 }, [0.32, 0.5]),
        move('cKemPriv', 'b.slot2', [0.44, 0.6]),
        move('ecdhC', 'b.op', [0.5, 0.64]),
        move('ecdhS', 's.op', [0.5, 0.64]),
        move('kemS', 's.op', [0.5, 0.64]),
        vanish('ecdhC', [0.66, 0.74]),
        vanish('kemC', [0.66, 0.74]),
        vanish('ecdhS', [0.66, 0.74]),
        vanish('kemS', [0.66, 0.74]),
        appear('secretC', 'b.op', [0.66, 0.76]),
        appear('secretS', 's.op', [0.66, 0.76]),
        set('secretC', { formed: 1 }, [0.66, 0.8]),
        set('secretS', { formed: 1 }, [0.66, 0.8]),
        move('secretC', 'b.slot4', [0.84, 1]),
        move('secretS', 's.slot7', [0.84, 1]),
      ],
    });
  }
  const secretC = kem ? 'secretC' : 'ecdhC';
  const secretS = kem ? 'secretS' : 'ecdhS';
  beat({
    id: 'derive',
    seconds: 7,
    layer: 'tls',
    caption: 'From the secret, both sides derive the keys that will encrypt everything from here on.',
    detail: `The TLS 1.3 key schedule (HKDF). Channel key: ${hex(session.channelKey)}…`,
    ...SIMPLIFIED,
    ops: [
      { actor: 'b', label: 'Derive keys', span: OPERATE_SPAN },
      { actor: 's', label: 'Derive keys', span: OPERATE_SPAN },
    ],
    actions: [
      ...operate('b', { inputs: [{ prop: secretC, back: 'b.slot4' }], output: { prop: 'keyC', to: 'b.slot5' } }),
      ...operate('s', { inputs: [{ prop: secretS, back: 's.slot7' }], output: { prop: 'keyS', to: 's.slot8' } }),
      set('wire', { sealed: 1 }, [0.8, 1]),
    ],
  });

  // ------------------------------------------------------------------ Secure channel: the server proves who it is
  beat({
    id: 'sign',
    seconds: 9,
    layer: 'tls',
    landmark: { id: 'secure-channel', label: 'Secure channel' },
    caption: 'A secret shared with a stranger says nothing about who the stranger is. So the server signs a record of the conversation with the private key of its certificate.',
    detail: `CertificateVerify: a ${mode.signatureName} signature over a hash of every handshake message so far, ${sigBytes} bytes.`,
    ...SIMPLIFIED,
    ops: [{ actor: 's', label: 'Sign', span: OPERATE_SPAN }],
    actions: [appear('said', 's.work', [0, 0.1]), ...operate('s', { inputs: [{ prop: 'certKey', back: 's.slot1' }, { prop: 'said' }], output: { prop: 'cvSig', to: 's.tls2' } }), appear('certSent', 's.slot2', [0.7, 0.78]), move('certSent', 's.tls', [0.8, 1])],
  });
  beat({
    id: 'send-proof',
    seconds: 7,
    layer: 'tls',
    caption: 'It sends the certificate and the signature. These already travel encrypted.',
    detail: 'In TLS 1.3 everything after the ServerHello is encrypted, including the certificate.',
    ...SIMPLIFIED,
    actions: [move('certSent', 'b.tls', [0, 0.8]), move('cvSig', 'b.tls2', [0.05, 0.85]), move('certSent', 'b.slot6', [0.84, 1]), move('cvSig', 'b.slot3', [0.88, 1]), ...record('mFlight', 'tls', kem ? 'm.slot5' : 'm.slot3', 0.36)],
  });
  beat({
    id: 'check-cert',
    seconds: 7,
    layer: 'tls',
    caption: 'The browser checks that an authority it already trusts vouches for this certificate.',
    detail: 'The certificate carries the server’s public key and a certificate authority’s signature binding it to the name payroll.example.',
    ...SIMPLIFIED,
    actions: [move('certSent', 'b.trust', [0.05, 0.4]), set('trust', { checked: 1 }, [0.45, 0.7]), move('certSent', 'b.slot6', [0.75, 1])],
  });
  beat({
    id: 'verify',
    seconds: 9,
    layer: 'tls',
    caption: 'Then it checks the signature with the public key from the certificate. It matches: whoever is on the other end holds the certificate’s private key.',
    detail: `${mode.signatureName} verification over the browser’s own record of the handshake returned ${session.certificateVerifyValid}.`,
    ...SIMPLIFIED,
    ops: [{ actor: 'b', label: 'Verify', span: OPERATE_SPAN, result: { ok: session.certificateVerifyValid, text: 'It is payroll.example' } }],
    actions: [appear('saidC', 'b.hold2', [0, 0.1]), move('saidC', 'b.op', [0.12, 0.34]), vanish('saidC', [0.4, 0.55]), ...operate('b', { inputs: [{ prop: 'certSent', back: 'b.slot6' }, { prop: 'cvSig' }] })],
  });
  beat({
    id: 'finished',
    seconds: 6,
    layer: 'tls',
    caption: 'Both sides confirm they saw the same handshake. The channel is open.',
    detail: `Finished messages: a MAC over the whole handshake, keyed from the shared secret. Verified: ${session.finishedValid}.`,
    ...SIMPLIFIED,
    actions: [set('wire', { tunnel: 1 }, [0.15, 0.9])],
  });

  // ------------------------------------------------------------------ Authentication: the application's job
  beat({
    id: 'encrypt',
    seconds: 9,
    layer: 'application',
    landmark: { id: 'authentication', label: 'Authentication' },
    caption: 'Now the login can go. The browser encrypts it with the channel key.',
    detail: 'AES-256-GCM, as one TLS record. The bytes shown are the real ciphertext.',
    ...SIMPLIFIED,
    ops: [{ actor: 'b', label: 'Encrypt', span: OPERATE_SPAN }],
    actions: [...operate('b', { inputs: [{ prop: 'keyC', back: 'b.slot5' }, { prop: 'cred', back: 'b.app', changes: true }] }), set('cred', { cipher: 1 }, [0.38, 0.72])],
  });
  beat({
    id: 'send-login',
    seconds: 7,
    layer: 'application',
    caption: 'On the network it is noise.',
    detail: `${session.loginRecord.length} bytes: ${hex(session.loginRecord.subarray(5), 10)}…`,
    ...SIMPLIFIED,
    actions: [move('cred', 's.app', [0, 0.85]), move('cred', 's.work', [0.88, 1]), ...record('mLogin', 'app', kem ? 'm.slot6' : 'm.slot4', 0.38)],
  });
  beat({
    id: 'decrypt',
    seconds: 8,
    layer: 'application',
    caption: 'The server decrypts it with the same key.',
    detail: `AES-256-GCM decryption gave back: ${session.loginDecrypted.split('\n')[1] ?? ''}`,
    ...SIMPLIFIED,
    ops: [{ actor: 's', label: 'Decrypt', span: OPERATE_SPAN }],
    actions: [...operate('s', { inputs: [{ prop: 'keyS', back: 's.slot8' }, { prop: 'cred', back: 's.work', changes: true }] }), set('cred', { cipher: 0 }, [0.38, 0.72])],
  });
  beat({
    id: 'check-password',
    seconds: 8,
    layer: 'application',
    caption: 'And checks the password against what it has stored. This is the login itself, and TLS has no part in it.',
    detail: 'The application compares the password with a stored hash. No public-key cryptography is involved.',
    ...SIMPLIFIED,
    ops: [{ actor: 's', label: 'Check password', span: OPERATE_SPAN, result: { ok: true, text: 'It is Alice' } }],
    actions: operate('s', { inputs: [{ prop: 'pwStore', back: 's.slot9' }, { prop: 'cred' }] }),
  });
  beat({
    id: 'issue-token',
    seconds: 10,
    layer: 'application',
    caption: 'So that Alice need not send her password again, the server writes a token saying who she is, and signs it. This is a different private key from the certificate’s.',
    detail: `A JWT signed with ${mode.signatureAlg}, ${tokenBytes} bytes. Signing does not encrypt: anyone holding the token can read it.`,
    ...SIMPLIFIED,
    ops: [{ actor: 's', label: 'Sign', span: OPERATE_SPAN }],
    actions: [appear('claims', 's.work', [0, 0.1]), ...operate('s', { inputs: [{ prop: 'tokenKey', back: 's.slot3' }, { prop: 'claims' }], output: { prop: 'token', to: 's.app' } })],
  });
  beat({
    id: 'send-token',
    seconds: 6,
    layer: 'application',
    caption: 'The token goes back through the channel.',
    detail: 'Inside the encrypted channel, so only Alice’s browser receives it.',
    ...SIMPLIFIED,
    actions: [move('token', 'b.app', [0, 0.82]), move('token', 'b.hold', [0.86, 1])],
  });

  // ------------------------------------------------------------------ Success
  beat({
    id: 'use-token',
    seconds: 6,
    layer: 'application',
    landmark: { id: 'success', label: 'Success' },
    caption: 'From now on each request carries the token instead of the password.',
    detail: 'Authorization: Bearer <token>, through the same channel.',
    ...SIMPLIFIED,
    actions: [move('token', 'b.app', [0.05, 0.2]), move('token', 's.app', [0.22, 0.86]), move('token', 's.work', [0.9, 1])],
  });
  beat({
    id: 'verify-token',
    seconds: 9,
    layer: 'application',
    caption: 'The server checks the token’s signature with the matching public key. Any app holding that public key can check it; only the private key can make one.',
    detail: `${mode.signatureAlg} verification returned ${session.tokenValid}.`,
    ...SIMPLIFIED,
    ops: [{ actor: 's', label: 'Verify', span: OPERATE_SPAN, result: { ok: session.tokenValid, text: 'Signed by this service' } }],
    actions: [appear('tokenPub', 's.slot3', [0, 0.08]), ...operate('s', { inputs: [{ prop: 'tokenPub' }, { prop: 'token', back: 's.work' }] })],
  });
  beat({
    id: 'welcome',
    seconds: 5,
    layer: 'application',
    caption: 'Alice is in.',
    detail: 'Three layers did three jobs: key establishment made the channel private, a certificate signature said who the server is, and a token signature says who Alice is.',
    ...SIMPLIFIED,
    actions: [set('screen', { welcome: 1 }, [0.1, 0.6])],
  });

  // ------------------------------------------------------------------ The attack
  if (attack) {
    const quantum = attack.attacker === 'quantum';
    const machine = quantum ? 'a large quantum computer' : 'an ordinary computer';
    const loginSlot = kem ? 'm.slot6' : 'm.slot4';
    beat({
      id: 'recorded',
      seconds: 8,
      layer: 'attacker',
      landmark: { id: 'harvest', label: 'Recorded traffic' },
      caption: 'Mallory was on the network the whole time. She has a copy of everything that crossed it: the public halves, and encrypted records she cannot read.',
      detail: 'She never had either private half, the shared secret, or any of the server’s private keys. None of those were sent.',
      mark: 'model',
      honesty: 'A passive attacker. Recording traffic to attack it later is called “harvest now, decrypt later”.',
      actions: [],
    });
    beat({
      id: 'recover-private',
      seconds: 10,
      layer: 'attacker',
      caption: quantum
        ? 'Years later she has a large quantum computer. It turns the browser’s public half into its private half.'
        : 'She tries to work out a private half from a public half. With an ordinary computer that search would outlast the universe.',
      detail: quantum
        ? 'Shor’s algorithm solves the elliptic-curve discrete logarithm problem that X25519 relies on.'
        : 'The best known classical attack on X25519 needs about 2^126 operations.',
      ...(quantum ? CONCEPTUAL : HARDNESS),
      ops: [{ actor: 'm', label: quantum ? 'Shor’s algorithm' : 'Search', span: [0.24, 0.8], result: { ok: quantum, text: quantum ? 'Private half recovered' : 'No private half' } }],
      actions: quantum
        ? operate('m', { inputs: [{ prop: 'mCPub', back: 'm.slot1' }], output: { prop: 'mPriv', to: 'm.work1' } })
        : [move('mCPub', 'm.opA', [0, 0.22]), move('mCPub', 'm.op', [0.24, 0.36]), move('mCPub', 'm.slot1', [0.82, 1])],
    });
    if (quantum) {
      beat({
        id: 'recover-secret',
        seconds: 9,
        layer: 'attacker',
        caption: kem
          ? 'With it she redoes the X25519 half of the key exchange. The other half of the secret came from ML-KEM, and no quantum algorithm is known that opens that box.'
          : 'With it she does exactly what the browser did: combines the private half with the server’s public half, and has the shared secret.',
        detail: kem ? 'ML-KEM rests on a lattice problem for which neither classical nor quantum shortcuts are known.' : `She computes ${hex(session.sharedSecret)}…, the same value as both sides.`,
        ...REAL,
        ops: [{ actor: 'm', label: 'Combine', span: OPERATE_SPAN, result: { ok: attack.recoveredSharedSecret, text: attack.recoveredSharedSecret ? 'She has the secret' : 'Only half a secret' } }],
        actions: operate('m', { inputs: [{ prop: 'mPriv', back: 'm.work1' }, { prop: 'mSPub', back: kem ? 'm.slot3' : 'm.slot2' }], output: { prop: 'mSecret', to: 'm.work2' } }),
      });
    }
    beat({
      id: 'decrypt-recording',
      seconds: 9,
      layer: 'attacker',
      caption: attack.decryptedLogin
        ? 'She derives the same channel key and decrypts her recording. Alice’s password, years after the login.'
        : quantum
          ? 'Half a secret derives the wrong key. The recording stays noise.'
          : 'Without the secret there is no key. The recording stays noise.',
      detail: attack.decryptedLogin ? `AES-256-GCM opened the recorded bytes: ${attack.decryptedLogin.split('\n')[1] ?? ''}` : 'AES-256-GCM rejects a wrong key outright: the authentication tag does not verify.',
      ...(quantum ? REAL : { mark: 'simulation' as const, honesty: 'She has nothing to try. AES-256 itself is not what an attacker goes after.' }),
      ops: [{ actor: 'm', label: 'Decrypt', span: OPERATE_SPAN, result: { ok: attack.decryptedLogin !== undefined, text: attack.decryptedLogin ? 'Password read' : 'Unreadable' } }],
      actions: [
        ...(quantum ? [move('mSecret', 'm.opA', [0, 0.22]), move('mSecret', 'm.work2', [0.76, 1])] : []),
        move('mLogin', 'm.opB', [0, 0.22]),
        move('mLogin', 'm.op', [0.24, 0.36]),
        ...(attack.decryptedLogin ? [set('mLogin', { cipher: 0 }, [0.4, 0.72])] : []),
        move('mLogin', loginSlot, [0.78, 1]),
      ],
    });
    beat({
      id: 'recover-token-key',
      seconds: 10,
      layer: 'attacker',
      landmark: { id: 'forgery', label: 'Forgery' },
      caption: attack.recoveredTokenKey
        ? 'Now the signatures. The token public key is published for every app to use. Her quantum computer turns it into the private key.'
        : quantum
          ? 'Now the signatures. The token public key is published, but it is an ML-DSA key, and her quantum computer has no way in.'
          : 'Now the signatures. The token public key is published, but an ordinary computer cannot turn it into the private key.',
      detail: attack.recoveredTokenKey
        ? `Shor’s algorithm again, on ${mode.signatureName}. The same would work on the certificate key, letting her pose as the server to new visitors.`
        : pqSig
          ? 'ML-DSA rests on lattice problems. No quantum algorithm is known that recovers the key.'
          : `Recovering a ${mode.signatureName} private key classically is as hard as breaking the key exchange was.`,
      ...(quantum ? CONCEPTUAL : HARDNESS),
      ops: [{ actor: 'm', label: quantum ? 'Shor’s algorithm' : 'Search', span: OPERATE_SPAN, result: { ok: attack.recoveredTokenKey, text: attack.recoveredTokenKey ? 'Private key recovered' : 'No private key' } }],
      actions: [
        appear('mTokenPub', 's.slot3', [0, 0.06]),
        move('mTokenPub', 'm.opA', [0.06, 0.22]),
        move('mTokenPub', 'm.op', [0.24, 0.36]),
        ...(attack.recoveredTokenKey ? [appear('mTokenKey', 'm.op', [0.38, 0.5]), set('mTokenKey', { formed: 1 }, [0.38, 0.74])] : []),
        move('mTokenPub', 'm.work3', [0.76, 1]),
        ...(attack.recoveredTokenKey ? [move('mTokenKey', 'm.work4', [0.78, 1])] : []),
      ],
    });
    beat({
      id: 'forge',
      seconds: 9,
      layer: 'attacker',
      caption: attack.recoveredTokenKey ? 'She writes a token that says she is Alice and signs it with the real key.' : 'She writes a token that says she is Alice and signs it with a key of her own, since that is all she has.',
      detail: `A JWT signed with ${mode.signatureAlg}. ${attack.recoveredTokenKey ? 'It is indistinguishable from one the server made.' : 'The signature is valid for her key, not the server’s.'}`,
      ...REAL,
      ops: [{ actor: 'm', label: 'Sign', span: OPERATE_SPAN }],
      actions: [
        ...(attack.recoveredTokenKey ? [] : [appear('mTokenKey', 'm.work4', [0, 0.1]), set('mTokenKey', { formed: 1 }, [0, 0.1])]),
        ...operate('m', { inputs: [{ prop: 'mTokenKey', back: 'm.work4' }], output: { prop: 'mToken', to: 'm.out' } }),
      ],
    });
    beat({
      id: 'present-forgery',
      seconds: 10,
      layer: 'attacker',
      caption: attack.forgeryAccepted
        ? 'The server checks the signature with its public key. It verifies. Mallory is in as Alice, and never needed a password.'
        : 'The server checks the signature with its public key. It does not verify. She is turned away.',
      detail: `Real ${mode.signatureAlg} verification of her token returned ${attack.forgeryAccepted}.`,
      ...REAL,
      ops: [{ actor: 's', label: 'Verify', span: [0.5, 0.86], result: { ok: attack.forgeryAccepted, text: attack.forgeryAccepted ? 'Accepted as Alice' : 'Rejected' } }],
      actions: [move('mToken', 's.app', [0, 0.36]), move('mToken', 's.opB', [0.38, 0.48]), move('tokenPub', 's.opA', [0.38, 0.48]), appear('tokenPub', 's.slot3', [0.3, 0.36]), move('mToken', 's.op', [0.5, 0.6]), move('tokenPub', 's.op', [0.5, 0.6]), move('mToken', 's.work2', [0.88, 1]), vanish('tokenPub', [0.88, 1])],
    });
    beat({
      id: 'verdict',
      seconds: 9,
      layer: 'attacker',
      caption: verdict(session, attack),
      detail: 'The encryption itself was never the target. Quantum computers weaken AES-256 only slightly (Grover’s algorithm), leaving about 128 bits of security. The public-key steps around it are what break.',
      mark: 'model',
      honesty: 'The difference in timing is the point: recorded traffic can be attacked later; a signature has to be forged while it still matters.',
      actions: [],
    });
  }

  // ---- turn lengths into start and end times
  const beats: LoginBeat[] = [];
  const landmarks: Landmark[] = [];
  let clock = 0;
  for (const { seconds, landmark, ...rest } of specs) {
    if (landmark) landmarks.push({ ...landmark, t: clock });
    beats.push({ ...rest, start: clock, end: clock + seconds });
    clock += seconds;
  }
  return { duration: clock, props, beats, landmarks };
}

function verdict(session: Session, attack: AttackOutcome): string {
  const read = attack.decryptedLogin !== undefined;
  const forged = attack.forgeryAccepted;
  if (attack.attacker === 'classical') return 'With an ordinary computer she gets nothing: not the recording, not a forged login. This is why today’s cryptography is still trusted today.';
  if (read && forged) return 'Both layers fell, but not alike. The recorded login was readable years after the fact. The forgery only worked because the server still trusts that key today.';
  if (forged) return 'The recording stayed private: hybrid key exchange did its job. The forgery still worked, because the signatures are still classical. A quantum-safe connection is not a quantum-safe login.';
  if (read) return 'The recording was readable, though the signatures held.';
  return `Nothing fell. ML-KEM kept the recording private and ${MODES[session.mode].signatureName} kept the token unforgeable.`;
}
