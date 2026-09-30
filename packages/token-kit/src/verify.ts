import { errors, jwtVerify } from 'jose';
import type { JWTPayload, JWTVerifyGetKey, ProtectedHeaderParameters } from 'jose';
import { base64urlToJson } from './base64url.ts';

/** Why a token was refused. Stable codes that tests and UIs can switch on. */
export type RejectionCode =
  | 'malformed'
  | 'unsecured'
  | 'alg-not-allowed'
  | 'unknown-key'
  | 'bad-signature'
  | 'expired'
  | 'claim-mismatch';

export class TokenRejectedError extends Error {
  readonly code: RejectionCode;

  constructor(code: RejectionCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'TokenRejectedError';
    this.code = code;
  }
}

export interface VerifyOptions {
  issuer: string;
  audience: string;
  /**
   * The algorithm allowlist. This is the most important setting here: it stops
   * "alg: none" and algorithm-confusion attacks, and it is how a legacy app ends
   * up rejecting post-quantum tokens it doesn't understand.
   */
  algorithms: string[];
  /** When set, the token's nonce claim must match (binds the token to one login attempt). */
  nonce?: string;
}

export interface VerifiedToken {
  payload: JWTPayload;
  header: ProtectedHeaderParameters;
}

/**
 * Verifies an OpenID Connect ID token's signature and core claims.
 *
 * `getKey` is normally jose's createRemoteJWKSet(jwks_uri), which picks the
 * provider's public key by `kid`. Keys embedded in the token header (`jwk`,
 * `jku`, `x5u`) are never trusted: the key always comes from the caller.
 */
export async function verifyIdToken(
  token: string,
  getKey: JWTVerifyGetKey,
  options: VerifyOptions,
): Promise<VerifiedToken> {
  let header: Record<string, unknown>;
  try {
    header = base64urlToJson(token.split('.')[0] ?? '');
  } catch (cause) {
    throw new TokenRejectedError('malformed', 'The token is not a well-formed JWT.', { cause });
  }

  if (typeof header.alg !== 'string' || header.alg.toLowerCase() === 'none') {
    throw new TokenRejectedError('unsecured', 'The token is not signed (alg "none"), so anyone could have written it.');
  }

  let verified: VerifiedToken;
  try {
    const { payload, protectedHeader } = await jwtVerify(token, getKey, {
      issuer: options.issuer,
      audience: options.audience,
      algorithms: options.algorithms,
      requiredClaims: ['sub', 'iat', 'exp'],
    });
    verified = { payload, header: protectedHeader };
  } catch (error) {
    throw explain(error, header.alg, options.algorithms);
  }

  if (options.nonce !== undefined && verified.payload.nonce !== options.nonce) {
    throw new TokenRejectedError('claim-mismatch', 'The token was issued for a different login attempt (nonce mismatch).');
  }
  return verified;
}

/** Turns jose's errors into plain-language reasons. */
function explain(error: unknown, alg: string, allowed: string[]): unknown {
  if (error instanceof errors.JOSEAlgNotAllowed) {
    return new TokenRejectedError(
      'alg-not-allowed',
      `The token is signed with ${alg}, but this app only accepts ${allowed.join(', ')}.`,
      { cause: error },
    );
  }
  if (error instanceof errors.JWKSNoMatchingKey) {
    return new TokenRejectedError('unknown-key', 'None of the trusted public keys matches this token.', {
      cause: error,
    });
  }
  if (error instanceof errors.JWSSignatureVerificationFailed) {
    return new TokenRejectedError('bad-signature', 'The signature does not match: the token was altered or forged.', {
      cause: error,
    });
  }
  if (error instanceof errors.JWTExpired) {
    return new TokenRejectedError('expired', 'The token has expired.', { cause: error });
  }
  if (error instanceof errors.JWTClaimValidationFailed) {
    return new TokenRejectedError('claim-mismatch', `The "${error.claim}" claim failed validation (${error.reason}).`, {
      cause: error,
    });
  }
  if (error instanceof errors.JOSEError) {
    return new TokenRejectedError('malformed', `The token could not be processed: ${error.message}`, { cause: error });
  }
  return error;
}
