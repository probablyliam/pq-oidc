/**
 * An encrypted token (JWE, RFC 7516, compact form), made in the browser with
 * Web Crypto: a fresh AES-256 content key encrypts the claims (A256GCM), and
 * RSA-OAEP-256 wraps that key for the recipient. This is how an OpenID
 * provider encrypts an ID token for a client that asked for it.
 */
import { bytesToBase64url, jsonToBase64url } from '@pq-oidc/token-kit/base64url';

const view = (bytes: Uint8Array) => bytes as Uint8Array<ArrayBuffer>;

export async function encryptJwt(claims: object, kid = 'example-encryption-key'): Promise<string> {
  const recipient = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, [
    'encrypt',
    'decrypt',
  ]);
  const header = jsonToBase64url({ alg: 'RSA-OAEP-256', enc: 'A256GCM', typ: 'JWT', kid });
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKey = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipient.publicKey, view(contentKey)));
  const aes = await crypto.subtle.importKey('raw', view(contentKey), 'AES-GCM', false, ['encrypt']);
  // The protected header, as it appears in the token, is the additional authenticated data.
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: view(iv), additionalData: view(new TextEncoder().encode(header)) }, aes, view(new TextEncoder().encode(JSON.stringify(claims)))),
  );
  return [header, bytesToBase64url(wrappedKey), bytesToBase64url(iv), bytesToBase64url(sealed.subarray(0, -16)), bytesToBase64url(sealed.subarray(-16))].join('.');
}
