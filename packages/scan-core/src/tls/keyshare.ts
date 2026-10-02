/**
 * Client key shares for the groups the scanner can complete a handshake with,
 * using Node's own crypto (OpenSSL 3.5: X25519, P-256, P-384, ML-KEM).
 *
 * Hybrid groups concatenate the two shares, and the two shared secrets, in an
 * order the drafts fix per group (draft-ietf-tls-ecdhe-mlkem §3):
 *
 *   X25519MLKEM768      share: ML-KEM key ‖ X25519      secret: ML-KEM ‖ X25519
 *   SecP256r1MLKEM768   share: P-256 point ‖ ML-KEM key secret: ECDH ‖ ML-KEM
 *   SecP384r1MLKEM1024  share: P-384 point ‖ ML-KEM key secret: ECDH ‖ ML-KEM
 */
import crypto from 'node:crypto';
import { GROUP } from './registry.ts';
import { WireError } from './wire.ts';

export interface KeyShare {
  group: number;
  /** What goes in the ClientHello. */
  publicBytes: Buffer;
  /** Combines our private half with the server's share. Throws WireError if the share is malformed. */
  sharedSecret(serverShare: Buffer): Buffer;
}

interface Part {
  publicBytes: Buffer;
  serverShareBytes: number;
  sharedSecret(serverShare: Buffer): Buffer;
}

const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

function x25519Part(privateBytes?: Buffer): Part {
  const privateKey = privateBytes
    ? crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519_PREFIX, privateBytes]), format: 'der', type: 'pkcs8' })
    : crypto.generateKeyPairSync('x25519').privateKey;
  const jwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
  return {
    publicBytes: Buffer.from(jwk.x!, 'base64url'),
    serverShareBytes: 32,
    sharedSecret(serverShare) {
      const publicKey = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: serverShare.toString('base64url') }, format: 'jwk' });
      // OpenSSL refuses small-order points, which is the all-zero check RFC 8446 §7.4.2 requires.
      return crypto.diffieHellman({ privateKey, publicKey });
    },
  };
}

function ecdhPart(curve: 'prime256v1' | 'secp384r1'): Part {
  const ecdh = crypto.createECDH(curve);
  const publicBytes = ecdh.generateKeys();
  return {
    publicBytes,
    serverShareBytes: publicBytes.length, // an uncompressed point: 65 or 97 bytes
    sharedSecret: (serverShare) => ecdh.computeSecret(serverShare),
  };
}

function mlKemPart(parameterSet: 'ml-kem-768' | 'ml-kem-1024'): Part {
  const { publicKey, privateKey } = crypto.generateKeyPairSync(parameterSet);
  const sizes = parameterSet === 'ml-kem-768' ? { key: 1184, ciphertext: 1088 } : { key: 1568, ciphertext: 1568 };
  // Node has no raw export for ML-KEM keys yet; the encapsulation key is the tail of the SPKI encoding.
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return {
    publicBytes: spki.subarray(spki.length - sizes.key),
    serverShareBytes: sizes.ciphertext,
    sharedSecret: (ciphertext) => crypto.decapsulate(privateKey, ciphertext),
  };
}

/** Builds a share from parts in the order given; the secret is the parts' secrets in the same order. */
function combine(group: number, parts: Part[]): KeyShare {
  const expected = parts.reduce((n, p) => n + p.serverShareBytes, 0);
  return {
    group,
    publicBytes: Buffer.concat(parts.map((p) => p.publicBytes)),
    sharedSecret(serverShare) {
      if (serverShare.length !== expected) {
        throw new WireError(`server key share is ${serverShare.length} bytes; this group requires ${expected}`);
      }
      let offset = 0;
      try {
        return Buffer.concat(
          parts.map((part) => {
            const slice = serverShare.subarray(offset, offset + part.serverShareBytes);
            offset += part.serverShareBytes;
            return part.sharedSecret(slice);
          }),
        );
      } catch (error) {
        throw new WireError(`server key share was rejected: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  };
}

const BUILDERS: Record<number, () => Part[]> = {
  [GROUP.x25519]: () => [x25519Part()],
  [GROUP.secp256r1]: () => [ecdhPart('prime256v1')],
  [GROUP.secp384r1]: () => [ecdhPart('secp384r1')],
  [GROUP.MLKEM768]: () => [mlKemPart('ml-kem-768')],
  [GROUP.MLKEM1024]: () => [mlKemPart('ml-kem-1024')],
  [GROUP.X25519MLKEM768]: () => [mlKemPart('ml-kem-768'), x25519Part()],
  [GROUP.SecP256r1MLKEM768]: () => [ecdhPart('prime256v1'), mlKemPart('ml-kem-768')],
  [GROUP.SecP384r1MLKEM1024]: () => [ecdhPart('secp384r1'), mlKemPart('ml-kem-1024')],
};

/** Can the scanner complete a key exchange in this group (rather than only recognise it)? */
export function canGenerateKeyShare(group: number): boolean {
  return group in BUILDERS;
}

export function generateKeyShare(group: number): KeyShare {
  const build = BUILDERS[group];
  if (!build) throw new Error(`No key share implementation for group 0x${group.toString(16)}`);
  return combine(group, build());
}

/** An X25519 share with a fixed private key, for replaying published traces. */
export function x25519KeyShareFromPrivate(privateBytes: Buffer): KeyShare {
  return combine(GROUP.x25519, [x25519Part(privateBytes)]);
}
