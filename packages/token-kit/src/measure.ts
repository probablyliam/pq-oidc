import { COOKIE_BYTE_LIMIT } from './algorithms.ts';
import { base64urlToBytes, base64urlToJson } from './base64url.ts';

export interface JwtMeasurement {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  alg: string;
  kid: string | undefined;
  /** Length of the compact token as sent over the wire (it is ASCII, so chars = bytes). */
  totalBytes: number;
  encodedHeaderBytes: number;
  encodedPayloadBytes: number;
  encodedSignatureBytes: number;
  /** Raw signature length after base64url decoding. */
  signatureBytes: number;
  /** Bytes a browser counts if the token is stored in a cookie called `cookieName`. */
  cookieBytes: number;
  fitsInCookie: boolean;
}

/**
 * Splits a compact JWS/JWT and measures each part. This does NOT verify
 * anything; use verifyIdToken for that.
 */
export function measureJwt(token: string, cookieName = 'id_token'): JwtMeasurement {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new TypeError('A compact JWT has exactly three dot-separated parts');
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  const header = base64urlToJson(encodedHeader);
  const payload = base64urlToJson(encodedPayload);
  const cookieBytes = cookieName.length + 1 + token.length;

  return {
    header,
    payload,
    alg: String(header.alg),
    kid: typeof header.kid === 'string' ? header.kid : undefined,
    totalBytes: token.length,
    encodedHeaderBytes: encodedHeader.length,
    encodedPayloadBytes: encodedPayload.length,
    encodedSignatureBytes: encodedSignature.length,
    signatureBytes: base64urlToBytes(encodedSignature).length,
    cookieBytes,
    fitsInCookie: cookieBytes <= COOKIE_BYTE_LIMIT,
  };
}
