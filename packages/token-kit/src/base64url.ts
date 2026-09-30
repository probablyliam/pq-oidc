/**
 * Minimal base64url helpers (RFC 4648 §5) that work in Node and browsers alike.
 */

export function base64urlToBytes(input: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) {
    throw new TypeError('Input is not base64url');
  }
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlToJson(input: string): Record<string, unknown> {
  const text = new TextDecoder().decode(base64urlToBytes(input));
  const value: unknown = JSON.parse(text);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('Expected a JSON object');
  }
  return value as Record<string, unknown>;
}

export function jsonToBase64url(value: unknown): string {
  return bytesToBase64url(new TextEncoder().encode(JSON.stringify(value)));
}
