import { beforeAll, describe, expect, it } from 'vitest';
import { cleanLogin, DEFAULT_LOGIN, LOGIN_LIMITS, loginRequest, passwordIn, runAttack, runSession } from './session.ts';
import type { Attack, Session, Setup } from './session.ts';

const classical: Setup = { kex: 'x25519', cert: 'ecdsa', token: 'ecdsa' };
const hybridKex: Setup = { kex: 'hybrid', cert: 'ecdsa', token: 'ecdsa' };
const allPq: Setup = { kex: 'hybrid', cert: 'mldsa', token: 'mldsa' };
const typed = { username: 'bob', password: 'tr0ub4&=dor' };

describe('one login, run for real', () => {
  let s: Session;
  beforeAll(async () => {
    s = await runSession(classical, typed);
  });

  it('derives the same secret on both sides, verifies the proofs, and the login decrypts to what was typed', () => {
    expect(s.secretsMatch).toBe(true);
    expect(s.certificateVerifyValid).toBe(true);
    expect(s.finishedValid).toBe(true);
    expect(s.loginDecrypted).toBe(loginRequest(typed));
    expect(s.tokenValid).toBe(true);
  });

  it('never lets the typed password cross the network in the clear', () => {
    expect(new TextDecoder().decode(s.loginRecord)).not.toContain('tr0ub4');
    expect([...s.loginRecord.subarray(0, 3)]).toEqual([0x17, 0x03, 0x03]); // a TLS application-data record
  });

  it('signs the token with a different key from the certificate', () => {
    expect(JSON.stringify(s.tokenKey.publicJwk)).not.toBe(JSON.stringify(s.certKey.publicJwk));
  });

  it('uses ML-KEM only for a hybrid key exchange, in the order X25519MLKEM768 defines', async () => {
    expect(s.kemPublicKey).toBeUndefined();
    expect(s.sharedSecret).toHaveLength(32);
    const h = await runSession(hybridKex, typed);
    expect(h.kemPublicKey).toHaveLength(1184);
    expect(h.sharedSecret).toHaveLength(64); // 32 (ML-KEM secret) + 32 (X25519 secret)
  });

  it('keeps the keys of the parts that did not change when one choice changes', async () => {
    const changed = await runSession({ ...classical, token: 'mldsa' }, typed, s);
    expect(changed.certKey.publicJwk).toEqual(s.certKey.publicJwk); // cert unchanged
    expect(changed.tokenKey.alg).toBe('ML-DSA-65'); // token did change
  });
});

describe('what an attacker gets, each result a real decryption or verification', () => {
  const attacks: Record<string, Attack> = {};
  beforeAll(async () => {
    for (const [name, setup] of [['classical', classical], ['hybrid', hybridKex], ['pq', allPq]] as const) {
      const session = await runSession(setup, typed);
      attacks[`${name}-ordinary`] = await runAttack(session, 'ordinary');
      attacks[`${name}-quantum`] = await runAttack(session, 'quantum');
    }
  });

  it('an ordinary computer gets nothing, whatever the site uses', () => {
    for (const name of ['classical', 'hybrid', 'pq']) {
      const a = attacks[`${name}-ordinary`]!;
      expect(a.key.decryptedLogin).toBeUndefined();
      expect(a.site.accepted).toBe(false);
      expect(a.token.accepted).toBe(false);
    }
  });

  it('a quantum computer reads a classical key exchange but not a hybrid one', () => {
    expect(passwordIn(attacks['classical-quantum']!.key.decryptedLogin ?? '')).toBe(typed.password);
    expect(attacks['hybrid-quantum']!.key.decryptedLogin).toBeUndefined();
    expect(attacks['pq-quantum']!.key.decryptedLogin).toBeUndefined();
  });

  it('a quantum computer forges a classical signature but not ML-DSA', () => {
    expect(attacks['classical-quantum']!.site.accepted).toBe(true);
    expect(attacks['classical-quantum']!.token.accepted).toBe(true);
    expect(attacks['pq-quantum']!.site.accepted).toBe(false);
    expect(attacks['pq-quantum']!.token.accepted).toBe(false);
  });

  it('shows a re-derived secret that matches the real one only when the whole exchange was classical', async () => {
    const classicalSession = await runSession(classical, typed);
    const hit = await runAttack(classicalSession, 'quantum');
    expect([...hit.key.derivedSecret!]).toEqual([...classicalSession.sharedSecret]);
    const hybridSession = await runSession(hybridKex, typed);
    const miss = await runAttack(hybridSession, 'quantum');
    expect([...miss.key.derivedSecret!]).not.toEqual([...hybridSession.sharedSecret]);
    expect([...miss.key.derivedSecret!.subarray(0, 32)]).toEqual(new Array(32).fill(0)); // the ML-KEM half she never got
    expect(attacks['classical-ordinary']!.key.derivedSecret).toBeUndefined();
    expect(attacks['classical-quantum']!.site.signature.length).toBeGreaterThan(0);
  });

  it('never claims to recover an ML-KEM or ML-DSA key', () => {
    for (const a of Object.values(attacks)) {
      expect(a.key.kemRecovered).toBe(false);
      if (a.site.keyRecovered) expect(attacks['classical-quantum']).toBeTruthy(); // only classical sigs are ever recovered
    }
    expect(attacks['pq-quantum']!.token.keyRecovered).toBe(false);
    expect(attacks['hybrid-quantum']!.key.ecdhRecovered).toBe(true); // the classical half does fall
  });
});

describe('the typed login', () => {
  it('falls back to the example for empty fields and cuts long ones to what the lab can show', () => {
    expect(cleanLogin({ username: '  ', password: '' })).toEqual(DEFAULT_LOGIN);
    const long = cleanLogin({ username: 'christopher-alexander', password: 'correct-horse-battery-staple' });
    expect(long.username).toHaveLength(LOGIN_LIMITS.username);
    expect(long.password).toHaveLength(LOGIN_LIMITS.password);
  });
});
