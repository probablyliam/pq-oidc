/**
 * Resolves a target's host name once, checks every address it returned, and
 * pins one. All later connections for that target go to the pinned address;
 * nothing resolves the name again. That single rule is the defence against
 * DNS rebinding (ADR 0007).
 */
import { lookup as dnsLookup } from 'node:dns/promises';
import net from 'node:net';
import { classifyAddress } from './address.ts';
import type { AddressVerdict } from './address.ts';
import { TargetRejected } from './policy.ts';
import type { Target } from './policy.ts';

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/** Injectable so tests can play a hostile DNS server. */
export type Lookup = (hostname: string) => Promise<ResolvedAddress[]>;

export const systemLookup: Lookup = async (hostname) => {
  const results = await dnsLookup(hostname, { all: true, verbatim: true });
  return results.map((r) => ({ address: r.address, family: r.family === 6 ? 6 : 4 }));
};

export interface PinnedTarget {
  hostname: string;
  port: number;
  /** The one address every connection for this target uses. */
  address: string;
  family: 4 | 6;
  /** Everything the name resolved to, for the report. */
  resolved: AddressVerdict[];
  isLab: boolean;
  /** False when the target was given as an IP address (no SNI is sent then). */
  hasHostname: boolean;
}

export interface ResolveOptions {
  lookup?: Lookup;
  timeoutMs?: number;
}

export async function resolveTarget(target: Target, options: ResolveOptions = {}): Promise<PinnedTarget> {
  const { hostname, port, isLab } = target;
  const base = { hostname, port, isLab };

  if (target.hostFamily) {
    const verdict = classifyAddress(hostname);
    if (!verdict.allowed && !isLab) {
      throw new TargetRejected('address-not-allowed', `${hostname} is not a public address: ${verdict.reason}.`);
    }
    return { ...base, address: hostname, family: target.hostFamily, resolved: [verdict], hasHostname: false };
  }

  const lookup = options.lookup ?? systemLookup;
  let answers: ResolvedAddress[];
  try {
    answers = await withTimeout(lookup(hostname), options.timeoutMs ?? 4000);
  } catch (error) {
    throw new TargetRejected('dns-failure', `Could not resolve ${hostname}: ${dnsReason(error)}.`);
  }
  // Never trust the resolver to return well-formed addresses.
  answers = answers.filter((a) => net.isIP(a.address) !== 0);
  if (answers.length === 0) throw new TargetRejected('dns-failure', `${hostname} did not resolve to any address.`);

  const resolved = answers.map((a) => classifyAddress(a.address));
  if (!isLab) {
    // One bad address refuses the whole name: a name that answers with both a
    // public and an internal address is either misconfigured or an attack.
    const bad = resolved.find((v) => !v.allowed);
    if (bad) {
      throw new TargetRejected('address-not-allowed', `${hostname} resolves to ${bad.address}, which is not a public address: ${bad.reason}.`);
    }
  }

  // Prefer IPv4: it is reachable from more places the scanner might run.
  const chosen = resolved.find((v) => v.family === 4) ?? resolved[0]!;
  return { ...base, address: chosen.address, family: chosen.family, resolved, hasHostname: true };
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

function dnsReason(error: unknown): string {
  const code = (error as { code?: string }).code;
  if (code === 'ENOTFOUND') return 'no such host';
  if (code === 'EAI_AGAIN') return 'the DNS server did not answer';
  return error instanceof Error ? error.message : 'lookup failed';
}
