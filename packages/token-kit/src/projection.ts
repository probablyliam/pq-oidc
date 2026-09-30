import { ALGORITHMS } from './algorithms.ts';
import type { SigningAlg } from './algorithms.ts';
import { jsonToBase64url } from './base64url.ts';
import { base64urlLength } from './limits.ts';
import { measureJwt } from './measure.ts';

export interface Projection {
  alg: SigningAlg;
  /** Exact size of the same token re-signed with `alg`. */
  totalBytes: number;
  headerBytes: number;
  payloadBytes: number;
  signatureBytes: number;
  /** Size of the Authorization header carrying it: "Authorization: Bearer <token>". */
  bearerHeaderBytes: number;
  /** Size of a cookie named `cookieName` holding it. */
  cookieBytes: number;
}

/**
 * Predicts, byte for byte, how big an existing JWT becomes when the same header
 * and claims are signed with another algorithm. Only the "alg" header value and
 * the signature change, and signature sizes are fixed by the standards, so this
 * is exact (the Token Lab re-signs the token for real to prove it).
 */
export function projectToken(token: string, alg: SigningAlg, cookieName = 'id_token'): Projection {
  const { header, encodedPayloadBytes } = measureJwt(token);
  const headerBytes = jsonToBase64url({ ...header, alg }).length;
  const signatureBytes = base64urlLength(ALGORITHMS[alg].signatureBytes);
  const totalBytes = headerBytes + 1 + encodedPayloadBytes + 1 + signatureBytes;
  return {
    alg,
    totalBytes,
    headerBytes,
    payloadBytes: encodedPayloadBytes,
    signatureBytes,
    bearerHeaderBytes: 'Authorization: Bearer '.length + totalBytes,
    cookieBytes: cookieName.length + 1 + totalBytes,
  };
}
