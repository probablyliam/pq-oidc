/**
 * Turns what a user typed into a target the scanner is willing to look at.
 *
 * Everything here is syntax: scheme, port, credentials, and hosts that are
 * plainly internal. It runs in the API (to refuse a request before queuing it)
 * and again in the worker. The decision that actually matters, which address
 * the name resolves to, is made in resolve.ts.
 *
 * No Node APIs: the web app uses the same function to explain a refusal
 * before sending anything.
 */
import { classifyAddress, ipFamily } from './address.ts';

export type RejectionCode =
  | 'invalid-url'
  | 'scheme-not-allowed'
  | 'credentials-in-url'
  | 'port-not-allowed'
  | 'hostname-not-allowed'
  | 'address-not-allowed'
  | 'dns-failure'
  | 'too-many-redirects';

/** A target the scanner refused, with a code tests and the UI can switch on. */
export class TargetRejected extends Error {
  readonly code: RejectionCode;

  constructor(code: RejectionCode, message: string) {
    super(message);
    this.name = 'TargetRejected';
    this.code = code;
  }
}

export interface TargetPolicy {
  /** Ports a scan may connect to. */
  allowedPorts: readonly number[];
  /**
   * Exact origins (scheme://host:port) exempt from the scheme, port and address
   * rules. For local test servers only; see ADR 0007.
   */
  labOrigins: readonly string[];
}

export const DEFAULT_POLICY: TargetPolicy = { allowedPorts: [443, 8443], labOrigins: [] };

export interface Target {
  /** Normalised URL without fragment. */
  url: URL;
  origin: string;
  /** Lowercase, no brackets, no trailing dot. */
  hostname: string;
  port: number;
  /** 4 or 6 when the host is an IP literal. */
  hostFamily: 0 | 4 | 6;
  isLab: boolean;
}

const MAX_URL_LENGTH = 2048;

/** Names that only mean something inside a private network (RFC 6761, RFC 6762, RFC 8375, RFC 9476 and common practice). */
const INTERNAL_SUFFIXES = ['localhost', 'local', 'internal', 'intranet', 'lan', 'home', 'corp', 'home.arpa', 'localdomain', 'svc'];

export function parseLabOrigins(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const url = new URL(entry);
      if (url.pathname !== '/' || url.search || url.hash) throw new Error(`Lab origin "${entry}" must be scheme://host:port only`);
      return url.origin;
    });
}

/**
 * Parses and checks a target. Throws TargetRejected with the reason.
 * `input` may omit the scheme ("example.com/login" means https).
 */
export function parseTarget(input: string, policy: TargetPolicy = DEFAULT_POLICY): Target {
  const text = input.trim();
  if (!text || text.length > MAX_URL_LENGTH) throw new TargetRejected('invalid-url', 'Enter the address of a login page or sign-in service.');

  let url: URL;
  try {
    // The WHATWG parser canonicalises numeric hosts: 2130706433, 0x7f.1 and 0177.0.0.1 all become 127.0.0.1.
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`);
  } catch {
    throw new TargetRejected('invalid-url', 'That is not a valid address.');
  }
  url.hash = '';

  const isLab = policy.labOrigins.includes(url.origin);
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  const port = url.port ? Number(url.port) : url.protocol === 'http:' ? 80 : 443;
  const hostFamily = ipFamily(hostname);
  const target: Target = { url, origin: url.origin, hostname, port, hostFamily, isLab };

  if (url.username || url.password) {
    throw new TargetRejected('credentials-in-url', 'Remove the username and password from the address.');
  }
  if (!isLab && url.protocol !== 'https:') {
    throw new TargetRejected('scheme-not-allowed', `Only https:// addresses can be scanned, not ${url.protocol}//.`);
  }
  if (!hostname) throw new TargetRejected('invalid-url', 'That address has no host name.');
  if (isLab) return target;

  if (!policy.allowedPorts.includes(port)) {
    throw new TargetRejected('port-not-allowed', `Port ${port} is not allowed. Allowed ports: ${policy.allowedPorts.join(', ')}.`);
  }

  if (hostFamily) {
    const verdict = classifyAddress(hostname);
    if (!verdict.allowed) {
      throw new TargetRejected('address-not-allowed', `${hostname} is not a public address: ${verdict.reason}.`);
    }
    return target;
  }

  // Single-label names only resolve through a search domain, which makes them internal by construction.
  if (!hostname.includes('.')) {
    throw new TargetRejected('hostname-not-allowed', `"${hostname}" is not a public host name.`);
  }
  if (INTERNAL_SUFFIXES.some((suffix) => hostname.endsWith(`.${suffix}`))) {
    throw new TargetRejected('hostname-not-allowed', `"${hostname}" is a private or special-use name.`);
  }
  return target;
}
