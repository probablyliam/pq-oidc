import { describe, expect, it } from 'vitest';
import { LOGIN_REQUEST, MODES, runAttack, runLogin } from './crypto.ts';
import type { Mode } from './crypto.ts';

const modes: Mode[] = ['classical', 'hybrid', 'pq'];

describe('a login in each mode', () => {
  it.each(modes)('%s: both sides agree on a secret, the server is verified, the request arrives intact', async (mode) => {
    const s = await runLogin(mode);
    expect(s.sharedSecret.browser).toEqual(s.sharedSecret.server);
    expect(s.handshakeVerified).toBe(true);
    expect(s.decryptedRequest).toBe(LOGIN_REQUEST);
    expect(s.tokenVerified).toBe(true);
    // What crosses the network is ciphertext, not the request.
    expect(new TextDecoder().decode(s.wire.encryptedRequest)).not.toContain('alice');
  });

  it('adds ML-KEM-768 to the key agreement in the hybrid and post-quantum modes (FIPS 203 sizes)', async () => {
    expect((await runLogin('classical')).wire.kemCipherText).toBeUndefined();
    const hybrid = await runLogin('hybrid');
    expect(hybrid.wire.kemPublicKey).toHaveLength(1184);
    expect(hybrid.wire.kemCipherText).toHaveLength(1088);
    expect(hybrid.sharedSecret.browser).toHaveLength(64); // 32 bytes ECDH + 32 bytes ML-KEM
  });

  it('signs with ML-DSA-65 only in the post-quantum mode (FIPS 204 signature size)', async () => {
    expect((await runLogin('hybrid')).wire.handshakeSignature).toHaveLength(64);
    expect((await runLogin('pq')).wire.handshakeSignature).toHaveLength(3309);
  });
});

describe('an attacker who recorded the exchange', () => {
  it.each(modes)('%s: a classical computer gets nothing', async (mode) => {
    const result = await runAttack(await runLogin(mode), 'classical');
    expect(result.readLogin).toBeUndefined();
    expect(result.forgeryAccepted).toBe(false);
  });

  it('classical mode, quantum computer: reads the recorded login and forges a token', async () => {
    const result = await runAttack(await runLogin('classical'), 'quantum');
    expect(result.readLogin).toBe(LOGIN_REQUEST);
    expect(result.forgeryAccepted).toBe(true);
  });

  it('hybrid connection, quantum computer: cannot read the login, but still forges a token', async () => {
    const result = await runAttack(await runLogin('hybrid'), 'quantum');
    expect(result.readLogin).toBeUndefined();
    expect(result.forgeryAccepted).toBe(true);
  });

  it('post-quantum mode, quantum computer: neither', async () => {
    const result = await runAttack(await runLogin('pq'), 'quantum');
    expect(result.readLogin).toBeUndefined();
    expect(result.forgeryAccepted).toBe(false);
  });

  it('matches what each mode claims about itself', async () => {
    for (const mode of modes) {
      const result = await runAttack(await runLogin(mode), 'quantum');
      expect(result.recoveredSharedSecret).toBe(!MODES[mode].keyAgreement.quantumSafe);
      expect(result.forgeryAccepted).toBe(!MODES[mode].signature.quantumSafe);
    }
  });
});
