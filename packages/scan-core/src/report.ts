/**
 * The shape of a scan report. Shared by the worker that produces it, the API
 * that stores it and the web app that draws it, so it has no Node imports.
 *
 * A report keeps the raw observations (what each probe saw) next to the
 * findings drawn from them, so every finding can show its evidence.
 */
import type { KeySummary } from '@pq-oidc/token-kit/readiness';
import type { KexClass } from './tls/registry.ts';

/** Bump when findings would change for the same observations. Stored with every report. */
export const ENGINE_VERSION = '1.1.0';

/** How a finding is known (ADR 0012). */
export type FindingKind =
  /** Read off the wire or from a document the target published. */
  | 'observation'
  /** A conclusion drawn from observations; the reasoning is in `detail`. */
  | 'inference'
  /** Looked for and not established; `detail` says why. */
  | 'undetermined';

export type LayerId = 'key-establishment' | 'server-authentication' | 'record-protection' | 'transport-policy' | 'token-signing' | 'dependencies';

export type Tone = 'good' | 'caution' | 'bad' | 'neutral';

/** Where in the learning pages a finding is explained. */
export type LearnLink =
  | { view: 'login'; landmark: Landmark; mode: LearnMode; attacker?: 'classical' | 'quantum' }
  | { view: 'token' };

export type Landmark = 'login' | 'key-establishment' | 'secure-channel' | 'authentication' | 'success' | 'harvest' | 'forgery';
export type LearnMode = 'classical' | 'hybrid' | 'pq';

export interface Evidence {
  label: string;
  value: string;
}

export interface Finding {
  /** Stable identifier, e.g. "kex.negotiated". Used to compare two reports. */
  id: string;
  layer: LayerId;
  kind: FindingKind;
  tone: Tone;
  title: string;
  detail: string;
  evidence?: Evidence[];
  /** For an inference: the findings it rests on. */
  basedOn?: string[];
  learn?: LearnLink;
}

/**
 * What a capable quantum computer would change for one layer. This is itself
 * an inference; the rule for each value is in ADR 0012.
 */
export type QuantumExposure =
  /** Classical key establishment: traffic recorded today can be decrypted later. */
  | 'harvest-now-decrypt-later'
  /** Protected for clients that negotiate a post-quantum group, exposed for those that do not. */
  | 'depends-on-client'
  /** Classical signatures: forgeable once such a computer exists, not retroactively. */
  | 'forgery-once-quantum'
  /** Symmetric primitives and hashes: weakened by Grover, not broken. */
  | 'reduced-margin'
  | 'no-known-attack'
  | 'not-applicable'
  | 'undetermined';

export interface LayerSummary {
  id: LayerId;
  name: string;
  /** One line: what is in use, e.g. "Hybrid: X25519MLKEM768". */
  headline: string;
  exposure: QuantumExposure;
  tone: Tone;
}

export type ProbeId = 'pq-capable-client' | 'classical-client' | 'tls12-client' | `group-${number}`;

/** One ClientHello and what came back. */
export interface ProbeResult {
  id: ProbeId;
  /** What the probe was for, in plain words. */
  purpose: string;
  offered: { versions: string[]; groups: number[]; keyShares: number[] };
  outcome: string;
  detail?: string;
  alert?: string;
  version?: number;
  cipherSuite?: number;
  group?: number;
  alpn?: string;
  signatureScheme?: number;
  signatureValid?: boolean;
  finishedValid?: boolean;
  serverGroups?: number[];
  clientCertificateRequested?: boolean;
  dhPrimeBits?: number;
  /** SHA-256 fingerprint of the leaf certificate this probe received. */
  leafFingerprint?: string;
  /** True when the first answer was a HelloRetryRequest and the probe was repeated with the requested share. */
  retried?: boolean;
  durationMs: number;
}

export interface GroupSupport {
  group: number;
  name: string;
  kex: KexClass;
  /** Undefined when the probe got no usable answer. */
  supported: boolean | undefined;
  evidence: string;
}

export type SignatureFamilyName = 'RSA' | 'ECDSA' | 'EdDSA' | 'ML-DSA' | 'SLH-DSA' | 'unknown';

export interface CertificateSummary {
  /** 0 is the leaf. */
  position: number;
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  expired: boolean;
  notYetValid: boolean;
  selfSigned: boolean;
  isCa: boolean;
  names: string[];
  key: { algorithm: string; family: SignatureFamilyName; bits?: number; curve?: string; quantumSafe: boolean };
  /** The signature on this certificate, made by its issuer. */
  signature: { algorithm: string; oid: string; family: SignatureFamilyName; hash?: string; quantumSafe: boolean };
  fingerprint256: string;
  pem: string;
}

export interface TrustResult {
  checked: boolean;
  /** The chain validated and matched the host name, according to `store`. */
  trusted?: boolean;
  error?: string;
  store: string;
}

export interface HttpHop {
  url: string;
  status?: number;
  location?: string;
  error?: string;
}

export interface CookieSummary {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
}

export interface TransportSummary {
  hops: HttpHop[];
  /** A redirect the scanner refused to follow, and why. */
  blockedRedirect?: { location: string; code: string; reason: string };
  hsts?: { raw: string; maxAge?: number; includeSubDomains: boolean; preload: boolean };
  cookies: CookieSummary[];
  /** What port 80 on the same address does with a plain HTTP request. */
  plainHttp?: { status?: number; location?: string; upgradesToHttps: boolean; error?: string };
  serverHeader?: string;
}

/**
 * What the address is, as far as one fetch of it shows.
 *   sign-in-service    it publishes OpenID Connect metadata: other sites send people here to log in
 *   sign-in-page       the HTML it served has a password field
 *   leads-to-sign-in   it redirects to another origin that is one of the above
 *   other              none of these was found (a form built later by JavaScript is not seen)
 */
export interface PageSummary {
  kind: 'sign-in-service' | 'sign-in-page' | 'leads-to-sign-in' | 'other';
  /** What the kind rests on, strongest first: published metadata, a password field, a username field, the address alone. */
  how?: 'metadata' | 'password-field' | 'username-field' | 'address';
  /** The origin the address redirected to, when it left the scanned one. */
  leadsTo?: string;
  evidence: { label: string; value: string }[];
}

export interface OidcSummary {
  found: boolean;
  /** Every URL tried, with what came back. */
  tried: { url: string; result: string }[];
  discoveryUrl?: string;
  issuer?: string;
  /** The `issuer` in the document equals the URL it was served from (OIDC Discovery §4.3). */
  issuerMatches?: boolean;
  idTokenAlgs?: string[];
  jwksUri?: string;
  jwksError?: string;
  keys?: KeySummary[];
}

export interface RelatedOrigin {
  origin: string;
  role: string;
}

export interface ScanReport {
  schema: 1;
  engine: string;
  target: { input: string; url: string; origin: string; hostname: string; port: number; lab: boolean };
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  network: { address: string; family: 4 | 6; resolved: string[] };
  /** False when no TCP connection could be made; the rest of the report is then mostly empty. */
  reachable: boolean;
  tls: { probes: ProbeResult[]; groupSupport: GroupSupport[] };
  certificates: CertificateSummary[];
  trust: TrustResult;
  transport: TransportSummary;
  oidc: OidcSummary;
  /** Absent in reports from engine 1.0. */
  page?: PageSummary;
  related: RelatedOrigin[];
  layers: LayerSummary[];
  findings: Finding[];
}

/** What an outside scan cannot see. Shown with every report. */
export const NOT_OBSERVABLE: readonly string[] = [
  'Connections behind the TLS terminator: service-to-service TLS, databases, message queues.',
  'How private keys are stored and who can reach them (HSM, KMS, files on disk).',
  'Which key-exchange groups your actual clients support: old browsers, mobile apps, API clients.',
  'Token signing, when the service publishes no OpenID Connect metadata.',
  'Third parties the application calls from its servers.',
  'HTTP/3 (QUIC). The scanner speaks TLS over TCP only.',
  'Whether anyone is recording this service’s traffic today.',
];
