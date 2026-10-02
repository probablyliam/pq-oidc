import { beforeAll, describe, expect, it } from 'vitest';
import { actionWindow, sceneAt, scoreProblems } from './engine.ts';
import type { Beat, Score } from './engine.ts';
import { knownAnchors, layoutFor } from './layout.ts';
import { buildScore } from './score.ts';
import type { LoginScore } from './score.ts';
import { cleanLogin, DEFAULT_LOGIN, LOGIN_REQUEST, loginRequest, MODES, passwordIn, runAttack, runSession } from './session.ts';
import type { AttackOutcome, Mode, Session } from './session.ts';

const MODE_IDS: Mode[] = ['classical', 'hybrid', 'pq'];
const sessions = {} as Record<Mode, Session>;
const attacks = {} as Record<Mode, Record<'classical' | 'quantum', AttackOutcome>>;

beforeAll(async () => {
  for (const mode of MODE_IDS) {
    sessions[mode] = await runSession(mode);
    attacks[mode] = { classical: await runAttack(sessions[mode], 'classical'), quantum: await runAttack(sessions[mode], 'quantum') };
  }
});

const beatOf = (score: Score, id: string): Beat => score.beats.find((b) => b.id === id)!;
/** The time at which the nth action on `prop` in beat `id` is `fraction` of the way through. */
function during(score: Score, id: string, prop: string, fraction: number, nth = 0): number {
  const beat = beatOf(score, id);
  const [start, end] = actionWindow(beat, beat.actions.filter((a) => a.prop === prop)[nth]!);
  return start + (end - start) * fraction;
}

describe('the login that runs behind the stage', () => {
  it.each(MODE_IDS)('%s: both sides derive the same secret, the proofs verify and the login decrypts', (mode) => {
    const s = sessions[mode];
    expect(s.secretsMatch).toBe(true);
    expect(s.certificateVerifyValid).toBe(true);
    expect(s.finishedValid).toBe(true);
    expect(s.loginDecrypted).toBe(LOGIN_REQUEST);
    expect(s.tokenValid).toBe(true);
    // A TLS application-data record: type 0x17, version 0x0303, then ciphertext that does not contain the password.
    expect([...s.loginRecord.subarray(0, 3)]).toEqual([0x17, 0x03, 0x03]);
    expect(new TextDecoder().decode(s.loginRecord)).not.toContain(DEFAULT_LOGIN.password);
  });

  it('uses ML-KEM only in the hybrid and post-quantum modes, in the order X25519MLKEM768 defines', () => {
    expect(sessions.classical.kemPublicKey).toBeUndefined();
    expect(sessions.classical.sharedSecret).toHaveLength(32);
    for (const mode of ['hybrid', 'pq'] as const) {
      const s = sessions[mode];
      expect(s.kemPublicKey).toHaveLength(1184);
      expect(s.kemCiphertext).toHaveLength(1088);
      // ML-KEM secret first, then the X25519 secret.
      expect([...s.sharedSecret]).toEqual([...s.kemSecret!, ...s.ecdhSecret]);
    }
  });

  it('signs the token with a different key from the certificate’s', () => {
    for (const mode of MODE_IDS) {
      const s = sessions[mode];
      expect(JSON.stringify(s.tokenKey.publicJwk)).not.toBe(JSON.stringify(s.certKey.publicJwk));
      expect(s.tokenKey.alg).toBe(MODES[mode].signatureAlg);
    }
  });
});

describe('what the attacker can do, by setup (each result is a real decryption or verification)', () => {
  it.each([
    ['classical', 'classical', false, false],
    ['classical', 'quantum', true, true],
    ['hybrid', 'classical', false, false],
    ['hybrid', 'quantum', false, true],
    ['pq', 'classical', false, false],
    ['pq', 'quantum', false, false],
  ] as const)('%s cryptography, %s computer: reads the recording %s, forges a login %s', (mode, computer, reads, forges) => {
    const outcome = attacks[mode][computer];
    expect(outcome.decryptedLogin !== undefined).toBe(reads);
    expect(outcome.forgeryAccepted).toBe(forges);
    if (reads) expect(outcome.decryptedLogin).toBe(LOGIN_REQUEST);
  });

  it('never claims a quantum computer breaks ML-KEM or ML-DSA', () => {
    expect(attacks.hybrid.quantum.recoveredEcdhPrivate).toBe(true); // the classical half does fall
    expect(attacks.hybrid.quantum.recoveredSharedSecret).toBe(false);
    expect(attacks.pq.quantum.recoveredTokenKey).toBe(false);
  });
});

describe('every score is well formed', () => {
  it.each(MODE_IDS.flatMap((mode) => (['none', 'classical', 'quantum'] as const).map((attacker) => [mode, attacker] as const)))('%s, attacker: %s', (mode, attacker) => {
    const score = buildScore(sessions[mode], attacker === 'none' ? undefined : attacks[mode][attacker]);
    expect(scoreProblems(score, knownAnchors(attacker !== 'none'))).toEqual([]);
    expect(score.landmarks.map((l) => l.id)).toEqual(['login', 'key-establishment', 'secure-channel', 'authentication', 'success', ...(attacker === 'none' ? [] : ['harvest', 'forgery'])]);
    expect(score.landmarks.map((l) => l.t)).toEqual([...score.landmarks.map((l) => l.t)].sort((a, b) => a - b));
  });

  it('the row and column arrangements define the same anchors', () => {
    for (const attacker of [false, true]) {
      expect(Object.keys(layoutFor('column', attacker).anchors).sort()).toEqual(Object.keys(layoutFor('row', attacker).anchors).sort());
    }
  });

  it('an attacker who is only watching shares every beat of the login with one who goes on to attack', () => {
    for (const mode of MODE_IDS) {
      const watched = buildScore(sessions[mode], undefined, true);
      const attacked = buildScore(sessions[mode], attacks[mode].quantum);
      expect(scoreProblems(watched, knownAnchors(true))).toEqual([]);
      // She is on the stage and recording, and that is all: the timeline ends with the login.
      expect(watched.props.some((p) => p.id === 'mLogin')).toBe(true);
      expect(watched.props.some((p) => p.id === 'mPriv')).toBe(false);
      expect(watched.beats.at(-1)!.id).toBe('welcome');
      expect(attacked.beats.slice(0, watched.beats.length)).toEqual(watched.beats);
      // So swapping one score for the other at the end of the login changes nothing already on the stage.
      const [a, b] = [sceneAt(watched, watched.duration), sceneAt(attacked, watched.duration)];
      for (const id of Object.keys(a.props)) expect(b.props[id], id).toEqual(a.props[id]);
    }
  });
});

describe('the login is the one the visitor typed', () => {
  const typed = { username: 'bob', password: 'tr0ub4 &=dor' };
  let session: Session;
  let quantum: AttackOutcome;
  beforeAll(async () => {
    session = await runSession('classical', typed);
    quantum = await runAttack(session, 'quantum');
  });

  it('is what gets encrypted, sent and decrypted', () => {
    expect(session.loginDecrypted).toBe(loginRequest(typed));
    expect(passwordIn(session.loginDecrypted)).toBe(typed.password);
    expect(new TextDecoder().decode(session.loginRecord)).not.toContain('tr0ub4');
  });

  it('is what the stage shows, and what a quantum attacker ends up reading', () => {
    const score = buildScore(session, quantum);
    expect(score.props.find((p) => p.id === 'cred')!.look!.plain).toBe(`password=${typed.password}`);
    // Her copy shows only what her own decryption of the recording gave back.
    expect(passwordIn(quantum.decryptedLogin!)).toBe(typed.password);
    expect(score.props.find((p) => p.id === 'mLogin')!.look!.plain).toBe(`password=${typed.password}`);
    expect(score.beats.find((b) => b.id === 'welcome')!.caption).toBe('Signed in as bob.');
    expect(score.beats.find((b) => b.id === 'present-forgery')!.caption).toMatch(/Mallory is in as bob/);
  });

  it('shows the attacker nothing when her decryption fails', async () => {
    const hybrid = await runSession('hybrid', typed);
    const outcome = await runAttack(hybrid, 'quantum');
    expect(outcome.decryptedLogin).toBeUndefined();
    expect(buildScore(hybrid, outcome).props.find((p) => p.id === 'mLogin')!.look!.plain).toBe('');
    expect(JSON.stringify(buildScore(hybrid, outcome).props.filter((p) => p.id.startsWith('m')))).not.toContain('tr0ub4');
  });

  it('falls back to the example for empty fields and cuts long ones to what a chip can show', () => {
    expect(cleanLogin({ username: '  ', password: '' })).toEqual(DEFAULT_LOGIN);
    expect(cleanLogin({ username: ' christopher ', password: 'a-very-long-password' })).toEqual({ username: 'christop', password: 'a-very-long' });
  });
});

describe('the stage is a function of time', () => {
  let score: LoginScore;
  beforeAll(() => {
    score = buildScore(sessions.hybrid, attacks.hybrid.quantum);
  });

  it('starts with only what exists before the login, and ends signed in', () => {
    const start = sceneAt(score, 0);
    expect(start.props.cred!.opacity).toBe(0);
    expect(start.props.cPub!.opacity).toBe(0);
    expect(start.props.certKey).toMatchObject({ opacity: 1, to: 's.slot1' });
    expect(start.props.tokenKey).toMatchObject({ opacity: 1, to: 's.slot3' });
    expect(start.props.screen!.channels).toMatchObject({ waiting: 0, welcome: 0 });
    const loggedIn = sceneAt(score, score.landmarks.find((l) => l.id === 'harvest')!.t);
    expect(loggedIn.props.screen!.channels.welcome).toBe(1);
  });

  it('a public key share dragged to the middle of its trip is in the middle of the network', () => {
    const half = sceneAt(score, during(score, 'client-hello', 'cPub', 0.5));
    expect(half.props.cPub).toMatchObject({ from: 'b.tls', to: 's.tls', opacity: 1 });
    expect(half.props.cPub!.p).toBeCloseTo(0.5, 5);
    const quarter = sceneAt(score, during(score, 'client-hello', 'cPub', 0.25));
    expect(quarter.props.cPub!.p).toBeGreaterThan(0);
    expect(quarter.props.cPub!.p).toBeLessThan(0.5);
  });

  it('a signature scrubbed to the midpoint of signing is half formed and has not left the server', () => {
    // In the 'sign' beat the signature's actions are: appear, form, leave.
    const mid = sceneAt(score, during(score, 'sign', 'cvSig', 0.5, 1));
    expect(mid.props.cvSig!.channels.formed).toBeCloseTo(0.5, 5);
    expect(mid.props.cvSig).toMatchObject({ from: 's.op', to: 's.op' });
    expect(mid.beat.id).toBe('sign');
    const before = sceneAt(score, beatOf(score, 'sign').start);
    expect(before.props.cvSig!.opacity).toBe(0);
    const after = sceneAt(score, beatOf(score, 'sign').end);
    expect(after.props.cvSig).toMatchObject({ to: 's.tls2', p: 1, opacity: 1 });
    expect(after.props.cvSig!.channels.formed).toBe(1);
  });

  it('the login is readable in the browser, scrambled on the network, and readable again on the server', () => {
    const cipherAt = (t: number) => sceneAt(score, t).props.cred!.channels.cipher!;
    expect(cipherAt(beatOf(score, 'encrypt').start)).toBe(0);
    // Halfway through the transformation itself: the action that drives the "cipher" channel.
    const encrypt = beatOf(score, 'encrypt');
    const [from, to] = actionWindow(encrypt, encrypt.actions.find((a) => a.set?.cipher !== undefined)!);
    expect(cipherAt((from + to) / 2)).toBeCloseTo(0.5, 5);
    expect(sceneAt(score, (from + to) / 2).props.cred).toMatchObject({ to: 'b.op', opacity: 1 }); // in the chamber, in full view
    expect(cipherAt(during(score, 'send-login', 'cred', 0.5))).toBe(1);
    expect(sceneAt(score, during(score, 'send-login', 'cred', 0.5)).props.cred).toMatchObject({ from: 'b.app', to: 's.app' });
    expect(cipherAt(beatOf(score, 'decrypt').end)).toBe(0);
  });

  it('the channel does not exist until the handshake is finished', () => {
    const tunnelAt = (t: number) => sceneAt(score, t).props.wire!.channels.tunnel!;
    expect(tunnelAt(beatOf(score, 'verify').end)).toBe(0);
    expect(tunnelAt(beatOf(score, 'finished').end)).toBe(1);
    // The credentials only move once it does.
    expect(sceneAt(score, beatOf(score, 'finished').end - 0.01).props.cred).toMatchObject({ to: 'b.hold', p: 1 });
  });

  it('gives the same picture for a time however the playhead got there', () => {
    const times = [0, 3.3, 17.25, 44.4, 61, 80.5, 99.9, 120, score.duration];
    const forwards = times.map((t) => sceneAt(score, t));
    const backwards = [...times].reverse().map((t) => sceneAt(score, t)).reverse();
    expect(backwards).toEqual(forwards);
    expect(sceneAt(score, 61)).toEqual(sceneAt(score, 61));
  });

  it('moves smoothly: no prop jumps between nearby frames while it is visible', () => {
    const layout = layoutFor('row', true);
    const at = (t: number) => {
      const scene = sceneAt(score, t);
      return Object.fromEntries(
        Object.entries(scene.props).map(([id, s]) => {
          const [a, b] = [layout.anchors[s.from], layout.anchors[s.to]];
          return [id, { x: a && b ? a.x + (b.x - a.x) * s.p : 0, y: a && b ? a.y + (b.y - a.y) * s.p : 0, opacity: s.opacity }];
        }),
      );
    };
    for (let t = 0; t < score.duration; t += 0.05) {
      const [now, next] = [at(t), at(t + 0.05)];
      for (const id of Object.keys(now)) {
        if (now[id]!.opacity < 0.2 || next[id]!.opacity < 0.2) continue; // it may be placed somewhere new while invisible
        expect(Math.hypot(next[id]!.x - now[id]!.x, next[id]!.y - now[id]!.y), `${id} at ${t.toFixed(2)}s`).toBeLessThan(40);
      }
    }
  });

  it('clamps times outside the score', () => {
    expect(sceneAt(score, -5)).toEqual(sceneAt(score, 0));
    expect(sceneAt(score, score.duration + 60).beat.id).toBe('verdict');
  });
});

describe('the attacker in the same environment', () => {
  const end = (score: Score) => sceneAt(score, score.duration);
  const loginEnd = (score: LoginScore) => sceneAt(score, score.landmarks.find((l) => l.id === 'harvest')!.t);

  it('copies only what crossed the network, and cannot read the encrypted part', () => {
    const scene = loginEnd(buildScore(sessions.classical, attacks.classical.quantum));
    expect(scene.props.mCPub).toMatchObject({ opacity: 1, to: 'm.slot1' });
    expect(scene.props.mSPub).toMatchObject({ opacity: 1, to: 'm.slot2' });
    expect(scene.props.mLogin!.channels.cipher).toBe(1);
    // Nothing private is among her props until she recovers it.
    expect(scene.props.mPriv!.opacity).toBe(0);
    expect(scene.props.mSecret!.opacity).toBe(0);
  });

  it('copies each thing at the moment it passes the tap, not before', () => {
    const score = buildScore(sessions.classical, attacks.classical.quantum);
    const hello = beatOf(score, 'client-hello');
    expect(sceneAt(score, hello.start + 0.2 * (hello.end - hello.start)).props.mCPub!.opacity).toBe(0);
    expect(sceneAt(score, hello.end).props.mCPub!.opacity).toBe(1);
  });

  it('quantum against classical: the recording becomes readable and the forgery is accepted', () => {
    const score = buildScore(sessions.classical, attacks.classical.quantum);
    expect(end(score).props.mLogin!.channels.cipher).toBe(0);
    expect(end(score).props.mPriv!.opacity).toBe(1);
    expect(beatOf(score, 'present-forgery').caption).toMatch(/Mallory is in as alice/);
    // The quantum step is marked as a simulation; what she does with the result is marked as real.
    expect(score.beats.find((b) => b.id === 'recover-private')!.mark).toBe('simulation');
    expect(score.beats.find((b) => b.id === 'decrypt-recording')!.mark).toBe('real');
    expect(score.beats.find((b) => b.id === 'client-hello')!.mark).toBe('model');
  });

  it('quantum against hybrid: the recording stays scrambled, the forgery still works', () => {
    const score = buildScore(sessions.hybrid, attacks.hybrid.quantum);
    expect(end(score).props.mLogin!.channels.cipher).toBe(1);
    expect(beatOf(score, 'decrypt-recording').caption).toMatch(/stays noise/);
    expect(beatOf(score, 'present-forgery').caption).toMatch(/Mallory is in as alice/);
    expect(beatOf(score, 'verdict').caption).toMatch(/A quantum-safe connection is not a quantum-safe login/);
  });

  it('quantum against post-quantum: nothing falls', () => {
    const score = buildScore(sessions.pq, attacks.pq.quantum);
    expect(end(score).props.mLogin!.channels.cipher).toBe(1);
    expect(score.props.find((p) => p.id === 'mTokenKey')!.look!.note).toBe('not the server’s');
    expect(beatOf(score, 'present-forgery').caption).toMatch(/does not verify/);
  });

  it('classical against classical: nothing falls, and no quantum step is shown', () => {
    const score = buildScore(sessions.classical, attacks.classical.classical);
    expect(score.beats.some((b) => b.id === 'recover-secret')).toBe(false);
    expect(end(score).props.mLogin!.channels.cipher).toBe(1);
    expect(beatOf(score, 'verdict').caption).toMatch(/With an ordinary computer she gets nothing/);
  });

  it('never says a quantum computer breaks the cipher itself', () => {
    for (const mode of MODE_IDS) {
      const text = JSON.stringify(buildScore(sessions[mode], attacks[mode].quantum).beats);
      expect(text).toMatch(/weaken AES-256 only slightly/);
      expect(text).not.toMatch(/breaks? (AES|everything)/i);
    }
  });
});
