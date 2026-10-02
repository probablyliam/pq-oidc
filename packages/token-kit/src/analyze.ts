/**
 * Reads a token and says what can be known from it, without verifying
 * anything and without any network access. Signature verification is a
 * separate step (signature.ts) whose result is folded in by `describeSignature`.
 *
 * The three things people confuse are kept apart in the output:
 *   encoding    the header and payload are base64url: readable by anyone
 *   signing     the third part: makes changes detectable, hides nothing
 *   encryption  only a JWE (five parts) hides its contents
 */
import { base64urlToBytes, base64urlToJson } from './base64url.ts';
import { describeJweAlg, describeJwsAlg } from './jose.ts';
import type { JweAlg, JwsAlg } from './jose.ts';
import type { SignatureCheck } from './signature.ts';

export type TokenFindingKind = 'observation' | 'inference' | 'undetermined';

export interface TokenFinding {
  id: string;
  kind: TokenFindingKind;
  tone: 'good' | 'caution' | 'bad' | 'neutral';
  title: string;
  detail: string;
  evidence?: { label: string; value: string }[];
}

export type TokenFormat = 'jws' | 'jwe' | 'opaque';

export interface TokenAnalysis {
  format: TokenFormat;
  header?: Record<string, unknown>;
  /** The claims, when the payload is a JSON object. */
  payload?: Record<string, unknown>;
  alg?: JwsAlg;
  jwe?: JweAlg & { enc: string };
  /** Bytes of each dot-separated part as written. */
  partBytes: number[];
  signatureBytes?: number;
  /** The `iss` claim, when it is an https URL an issuer's keys could be fetched from. */
  issuerUrl?: string;
  findings: TokenFinding[];
}

/** Tokens are a few kilobytes; ML-DSA ones under ten. Anything far beyond is not worth parsing. */
export const MAX_TOKEN_LENGTH = 64 * 1024;

/** Header parameters that tell a verifier where to find the key. Trusting them lets the token choose its own key. */
const KEY_PARAMETERS: Record<string, string> = {
  jwk: 'a public key embedded in the token',
  jku: 'a URL to fetch keys from',
  x5u: 'a URL to fetch a certificate from',
  x5c: 'an embedded certificate chain',
};

const CLAIM_MEANING: Record<string, string> = {
  iss: 'who issued the token',
  sub: 'who the token is about',
  aud: 'who the token is for',
  exp: 'when it stops being valid',
  nbf: 'when it starts being valid',
  iat: 'when it was issued',
  jti: 'a unique ID for this token',
  nonce: 'ties the token to one sign-in attempt',
  azp: 'the app that requested it',
  auth_time: 'when the user actually signed in',
  scope: 'what it grants access to',
  cnf: 'binds the token to a key held by the client',
};

function duration(seconds: number): string {
  const abs = Math.abs(seconds);
  if (abs < 90) return `${Math.round(abs)} seconds`;
  if (abs < 5400) return `${Math.round(abs / 60)} minutes`;
  if (abs < 129_600) return `${Math.round(abs / 3600)} hours`;
  return `${Math.round(abs / 86_400)} days`;
}

const show = (value: unknown): string => (typeof value === 'string' ? value : JSON.stringify(value));
const numericDate = (value: unknown): number | undefined => (typeof value === 'number' && Number.isFinite(value) ? value : undefined);
const iso = (seconds: number) => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');

function httpsIssuer(iss: unknown): string | undefined {
  if (typeof iss !== 'string') return undefined;
  try {
    const url = new URL(iss);
    return url.protocol === 'https:' ? iss : undefined;
  } catch {
    return undefined;
  }
}

export function analyzeToken(input: string, nowSeconds = Math.floor(Date.now() / 1000)): TokenAnalysis {
  const token = input.trim();
  const parts = token.split('.');
  const analysis: TokenAnalysis = { format: 'opaque', partBytes: parts.map((p) => p.length), findings: [] };
  const add = (finding: TokenFinding) => analysis.findings.push(finding);

  const opaque = (detail: string) => {
    add({
      id: 'format.opaque',
      kind: 'undetermined',
      tone: 'neutral',
      title: 'This is not a JWT, so nothing can be read from it',
      detail: `${detail} An opaque token is a reference: its meaning is stored by the server that issued it, and its cryptography, if any, is not visible in the token.`,
    });
    return analysis;
  };

  if (token.length > MAX_TOKEN_LENGTH) return opaque(`The input is ${token.length.toLocaleString('en-US')} characters, far larger than any token.`);
  if (parts.length !== 3 && parts.length !== 5) return opaque(`A JWT has three parts separated by dots (five if it is encrypted); this has ${parts.length}.`);

  let header: Record<string, unknown>;
  try {
    header = base64urlToJson(parts[0]!);
  } catch {
    return opaque('The first part is not base64url-encoded JSON.');
  }
  analysis.header = header;

  // ------------------------------------------------------------ encrypted (JWE)
  if (parts.length === 5) {
    analysis.format = 'jwe';
    const jwe = { ...describeJweAlg(header.alg), enc: typeof header.enc === 'string' ? header.enc : '(not named)' };
    analysis.jwe = jwe;
    add({
      id: 'format.encrypted',
      kind: 'observation',
      tone: 'neutral',
      title: 'This token is encrypted (JWE): its claims cannot be read without the recipient’s key',
      detail: 'Five parts: a header, an encrypted content key, an initialisation vector, the ciphertext and an authentication tag. Only the header is readable.',
      evidence: [
        { label: 'alg (how the content key is delivered)', value: `${jwe.alg || '(absent)'}: ${jwe.name}` },
        { label: 'enc (how the content is encrypted)', value: jwe.enc },
      ],
    });
    if (jwe.quantum === 'shor') {
      add({
        id: 'quantum.encrypted',
        kind: 'inference',
        tone: 'bad',
        title: 'A copy of this token kept today could be decrypted later by a quantum computer',
        detail: `The content key is protected with ${jwe.name}, which Shor’s algorithm breaks. Unlike a signature, encryption can be attacked in retrospect: anyone who stores the token now can read it once a large enough quantum computer exists.`,
      });
    } else if (jwe.quantum !== 'unknown') {
      add({
        id: 'quantum.encrypted',
        kind: 'inference',
        tone: 'good',
        title: 'A quantum computer does not help decrypt this token',
        detail: jwe.quantum === 'grover' ? 'The content key is protected with a symmetric key, which quantum computers only weaken slightly.' : 'The content key is protected with ML-KEM, for which no quantum attack is known.',
      });
    }
    return analysis;
  }

  // ------------------------------------------------------------ signed (JWS)
  analysis.format = 'jws';
  const alg = describeJwsAlg(header.alg);
  analysis.alg = alg;

  let payload: Record<string, unknown> | undefined;
  try {
    payload = base64urlToJson(parts[1]!);
  } catch {
    payload = undefined;
  }
  analysis.payload = payload;
  try {
    analysis.signatureBytes = base64urlToBytes(parts[2]!).length;
  } catch {
    analysis.signatureBytes = undefined;
  }

  add({
    id: 'format.encoding',
    kind: 'observation',
    tone: 'neutral',
    title: payload ? 'The claims are readable by anyone who holds this token' : 'The header is readable; the payload is not a JSON object',
    detail: payload
      ? 'The header and payload are base64url-encoded JSON. That is an encoding, not encryption: no key was needed to read them. Do not put anything in a token that its holder should not see.'
      : 'The payload decodes to something other than a JSON object, so this is a signed message rather than a set of claims.',
    evidence: [
      { label: 'Header', value: `${parts[0]!.length} bytes` },
      { label: 'Payload', value: `${parts[1]!.length} bytes` },
      { label: 'Signature', value: `${parts[2]!.length} bytes encoded${analysis.signatureBytes === undefined ? '' : `, ${analysis.signatureBytes} bytes raw`}` },
    ],
  });

  // ---- how it is protected
  const headerEvidence = [
    { label: 'alg', value: JSON.stringify(header.alg) ?? '(absent)' },
    ...(header.kid === undefined ? [] : [{ label: 'kid', value: String(header.kid) }]),
    ...(header.typ === undefined ? [] : [{ label: 'typ', value: String(header.typ) }]),
  ];
  if (alg.kind === 'none') {
    add({
      id: 'signature.algorithm',
      kind: 'observation',
      tone: 'bad',
      title: 'This token is not signed',
      detail: `The header declares alg "${alg.alg}". Anyone can write a token like this with any claims. A verifier must refuse it.${analysis.signatureBytes ? ' It still carries bytes in the signature position; they mean nothing.' : ''}`,
      evidence: headerEvidence,
    });
  } else if (alg.kind === 'hmac') {
    add({
      id: 'signature.algorithm',
      kind: 'observation',
      tone: 'neutral',
      title: `Protected with ${alg.alg}: a keyed hash, not a public-key signature`,
      detail: `${alg.name}. The issuer and every app that checks the token share one secret, so anything that can verify this token can also create one.`,
      evidence: headerEvidence,
    });
  } else if (alg.kind === 'unknown') {
    add({
      id: 'signature.algorithm',
      kind: 'undetermined',
      tone: 'neutral',
      title: alg.alg ? `The algorithm "${alg.alg}" is not one this tool knows` : 'The header names no algorithm',
      detail: 'Without knowing the algorithm nothing can be said about how the token is protected.',
      evidence: headerEvidence,
    });
  } else {
    add({
      id: 'signature.algorithm',
      kind: 'observation',
      tone: alg.quantum === 'no-known-attack' ? 'good' : 'neutral',
      title: `Signed with ${alg.alg}: ${alg.name}`,
      detail: 'The signature covers the header and the payload, so neither can be changed without it failing to verify. It does not hide them. The algorithm is the issuer’s choice and has nothing to do with the TLS connection the token travels over.',
      evidence: headerEvidence,
    });
  }

  if (alg.quantum === 'shor') {
    add({
      id: 'quantum.signature',
      kind: 'inference',
      tone: 'caution',
      title: 'A quantum computer could forge tokens like this one, once it exists',
      detail: `${alg.name} is broken by Shor’s algorithm: the issuer’s private key can be computed from its public key, and with it an attacker can sign any claims. This is not retroactive. A token that has expired cannot be made useful again, so the risk begins when such a computer exists.`,
    });
  } else if (alg.quantum === 'no-known-attack') {
    add({ id: 'quantum.signature', kind: 'inference', tone: 'good', title: 'No known quantum attack forges this signature', detail: `${alg.name} is one of the post-quantum signature standards.` });
  } else if (alg.kind === 'hmac') {
    add({
      id: 'quantum.signature',
      kind: 'inference',
      tone: 'neutral',
      title: 'A quantum computer does not break this, but HMAC has a classical limit',
      detail: 'Shor’s algorithm does not apply to keyed hashes, and Grover’s only shortens the search for the secret, which a 256-bit secret withstands. The limit is the shared secret itself: it has to be given to every verifier.',
    });
  }

  // ---- key material the token brings along
  const supplied = Object.keys(KEY_PARAMETERS).filter((name) => header[name] !== undefined);
  if (supplied.length > 0) {
    add({
      id: 'header.keys',
      kind: 'observation',
      tone: 'caution',
      title: `The header carries its own key material (${supplied.join(', ')})`,
      detail: 'This tool ignores it and never fetches a URL named in a token. A verifier that trusts a key or key address supplied by the token lets whoever wrote the token choose the key it is checked with.',
      evidence: supplied.map((name) => ({ label: name, value: KEY_PARAMETERS[name]! })),
    });
  }

  if (!payload) return analysis;

  // ---- time
  const exp = numericDate(payload.exp);
  const nbf = numericDate(payload.nbf);
  const iat = numericDate(payload.iat);
  const timeEvidence = [
    ...(iat === undefined ? [] : [{ label: 'iat (issued)', value: iso(iat) }]),
    ...(nbf === undefined ? [] : [{ label: 'nbf (not before)', value: iso(nbf) }]),
    ...(exp === undefined ? [] : [{ label: 'exp (expires)', value: iso(exp) }]),
  ];
  if (exp === undefined) {
    add({
      id: 'claims.time',
      kind: 'observation',
      tone: 'caution',
      title: 'The token has no expiry',
      detail: 'There is no "exp" claim, so the token itself never stops being valid. A stolen copy stays useful until the signing key is replaced.',
      evidence: timeEvidence.length > 0 ? timeEvidence : [{ label: 'exp', value: '(absent)' }],
    });
  } else {
    const expired = exp <= nowSeconds;
    const early = nbf !== undefined && nbf > nowSeconds;
    const lifetime = iat === undefined ? undefined : exp - iat;
    add({
      id: 'claims.time',
      kind: 'observation',
      tone: 'neutral',
      title: expired ? `Expired ${duration(nowSeconds - exp)} ago` : early ? `Not valid for another ${duration(nbf - nowSeconds)}` : `Valid for another ${duration(exp - nowSeconds)}`,
      detail: `${lifetime === undefined ? '' : `Issued with a lifetime of ${duration(lifetime)}. `}Expiry is a claim inside the token: it only means something if the signature is checked.`,
      evidence: timeEvidence,
    });
  }

  // ---- who and for whom
  const present = Object.keys(CLAIM_MEANING).filter((name) => payload[name] !== undefined && !['exp', 'nbf', 'iat'].includes(name));
  const missing = ['iss', 'sub', 'aud'].filter((name) => payload[name] === undefined);
  add({
    id: 'claims.identity',
    kind: 'observation',
    tone: 'neutral',
    title: missing.length === 0 ? 'It names an issuer, a subject and an audience' : `It has no ${missing.map((m) => `"${m}"`).join(' or ')} claim`,
    detail:
      missing.length === 0
        ? 'A verifier should check all three: that it trusts the issuer, and that the audience is itself. A valid signature on a token meant for a different app is still a token for a different app.'
        : 'Without these a verifier cannot tell who issued the token or whether it was meant for it.',
    evidence: present.map((name) => ({ label: `${name}: ${CLAIM_MEANING[name]}`, value: show(payload[name]) })),
  });

  analysis.issuerUrl = httpsIssuer(payload.iss);
  return analysis;
}

/** The finding for a signature check, or for the lack of one. */
export function describeSignature(analysis: TokenAnalysis, check: SignatureCheck | undefined, keySource?: string): TokenFinding {
  const from = keySource ? ` published at ${keySource}` : '';
  if (!check) {
    return {
      id: 'signature.check',
      kind: 'undetermined',
      tone: 'neutral',
      title: 'The signature has not been checked',
      detail: analysis.issuerUrl
        ? 'Checking it needs the issuer’s public keys. Everything above is what the token says about itself, which a forger controls.'
        : 'Checking it needs the issuer’s public keys, and this token does not name an https issuer to fetch them from. Everything above is what the token says about itself, which a forger controls.',
    };
  }
  switch (check.status) {
    case 'valid':
      return {
        id: 'signature.check',
        kind: 'observation',
        tone: 'good',
        title: `The signature verifies with a ${check.key.strength} key${from}`,
        detail: 'The header and payload are exactly what the holder of that key signed. This shows who signed the token; whether that issuer is one you should trust, and whether the token was meant for you, are separate questions.',
        evidence: [{ label: 'Key', value: `${check.key.kid ?? '(no kid)'}: ${check.key.strength}` }],
      };
    case 'invalid':
      return { id: 'signature.check', kind: 'observation', tone: 'bad', title: 'The signature does not verify', detail: check.detail, evidence: [{ label: 'Keys tried', value: String(check.triedKeys) }] };
    case 'unsigned':
      return { id: 'signature.check', kind: 'observation', tone: 'bad', title: 'There is no signature to check', detail: check.detail, evidence: [{ label: 'alg', value: String(analysis.header?.alg) }] };
    case 'not-verifiable':
      return { id: 'signature.check', kind: 'undetermined', tone: 'neutral', title: 'The signature could not be checked', detail: check.detail };
  }
}
