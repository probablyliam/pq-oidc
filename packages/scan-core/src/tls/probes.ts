/**
 * The set of handshakes one scan performs, and why each exists:
 *
 *   pq-capable-client   what a current browser gets: hybrid offered first
 *   classical-client    what a client with no post-quantum support gets
 *   tls12-client        whether TLS 1.2 is still accepted, and its key exchange
 *   group-N             one per post-quantum group: does the server accept it at all?
 *
 * Probes run one after another, each on its own connection to the pinned
 * address: around eight short handshakes per scan.
 */
import crypto from 'node:crypto';
import type { PinnedTarget } from '../net/resolve.ts';
import type { GroupSupport, ProbeId, ProbeResult } from '../report.ts';
import type { HandshakeObservation } from './handshake.ts';
import { canGenerateKeyShare, generateKeyShare } from './keyshare.ts';
import { observeHandshake } from './observe.ts';
import type { ObserveOptions, ProbeSpec } from './observe.ts';
import { GROUP, GROUPS, groupName, PQ_GROUPS_TO_ENUMERATE, SIGNATURE_SCHEMES_CLASSICAL, SIGNATURE_SCHEMES_WITH_PQ } from './registry.ts';

interface ProbePlan {
  id: ProbeId;
  purpose: string;
  versions: ('1.3' | '1.2')[];
  groups: number[];
  shareGroups: number[];
  signatureSchemes: readonly number[];
}

const CLASSICAL_GROUPS = [GROUP.x25519, GROUP.secp256r1, GROUP.secp384r1];

const PLANS: Record<'pq-capable-client' | 'classical-client' | 'tls12-client', ProbePlan> = {
  'pq-capable-client': {
    id: 'pq-capable-client',
    purpose: 'A client that supports post-quantum key exchange and ML-DSA signatures, as current browsers increasingly do',
    versions: ['1.3', '1.2'],
    groups: [GROUP.X25519MLKEM768, GROUP.x25519, GROUP.secp256r1, GROUP.SecP256r1MLKEM768, GROUP.SecP384r1MLKEM1024, GROUP.MLKEM768, GROUP.MLKEM1024, GROUP.secp384r1],
    shareGroups: [GROUP.X25519MLKEM768, GROUP.x25519],
    signatureSchemes: SIGNATURE_SCHEMES_WITH_PQ,
  },
  'classical-client': {
    id: 'classical-client',
    purpose: 'A client with no post-quantum support',
    versions: ['1.3', '1.2'],
    groups: CLASSICAL_GROUPS,
    shareGroups: [GROUP.x25519, GROUP.secp256r1],
    signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL,
  },
  'tls12-client': {
    id: 'tls12-client',
    purpose: 'A client that only speaks TLS 1.2',
    versions: ['1.2'],
    groups: CLASSICAL_GROUPS,
    shareGroups: [],
    signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL,
  },
};

const toSpec = (plan: ProbePlan): ProbeSpec => ({
  versions: plan.versions,
  groups: plan.groups,
  keyShares: plan.shareGroups.map(generateKeyShare),
  signatureSchemes: plan.signatureSchemes,
  alpn: ['h2', 'http/1.1'],
});

export interface TlsProbeSet {
  probes: ProbeResult[];
  groupSupport: GroupSupport[];
  /** DER chain from the best probe that returned one, leaf first. */
  certificates: Buffer[];
  reachable: boolean;
}

export interface ProbeOptions extends ObserveOptions {
  onProgress?: (step: string) => void;
}

async function run(pinned: PinnedTarget, plan: ProbePlan, options: ObserveOptions): Promise<{ result: ProbeResult; seen: HandshakeObservation }> {
  const started = Date.now();
  let seen = await observeHandshake(pinned, toSpec(plan), options);
  let retried = false;
  // A HelloRetryRequest means "I support this group, send me a share for it". Do that, on a new connection.
  if (seen.outcome === 'hello-retry-request' && plan.shareGroups.length > 0 && seen.group !== undefined && canGenerateKeyShare(seen.group)) {
    seen = await observeHandshake(pinned, toSpec({ ...plan, shareGroups: [seen.group] }), options);
    retried = true;
  }
  const { certificates, alert, ...rest } = seen;
  return {
    seen,
    result: {
      id: plan.id,
      purpose: plan.purpose,
      offered: { versions: plan.versions, groups: plan.groups, keyShares: plan.shareGroups },
      ...rest,
      alert: alert?.name,
      leafFingerprint: certificates?.[0] ? crypto.createHash('sha256').update(certificates[0]).digest('hex') : undefined,
      retried: retried || undefined,
      durationMs: Date.now() - started,
    },
  };
}

export async function probeTls(pinned: PinnedTarget, options: ProbeOptions = {}): Promise<TlsProbeSet> {
  const probes: ProbeResult[] = [];
  const progress = options.onProgress ?? (() => {});

  progress('TLS handshake as a post-quantum-capable client');
  const main = await run(pinned, PLANS['pq-capable-client'], options);
  probes.push(main.result);
  if (main.seen.outcome === 'unreachable') return { probes, groupSupport: [], certificates: [], reachable: false };

  progress('TLS handshake as a client without post-quantum support');
  const classical = await run(pinned, PLANS['classical-client'], options);
  probes.push(classical.result);

  // Two handshakes with no TLS answer at all: more would only keep a slow or silent server waiting.
  const silent = (p: { seen: HandshakeObservation }) => ['timeout', 'closed', 'not-tls', 'unreachable'].includes(p.seen.outcome);
  if (silent(main) && silent(classical)) return { probes, groupSupport: [], certificates: [], reachable: true };

  progress('TLS 1.2 handshake');
  const legacy = await run(pinned, PLANS['tls12-client'], options);
  probes.push(legacy.result);

  const groupSupport: GroupSupport[] = [];
  const speaks13 = [main, classical].some((p) => p.seen.version === 0x0304);
  let unanswered = 0;
  for (const group of PQ_GROUPS_TO_ENUMERATE) {
    const info = GROUPS[group]!;
    const base = { group, name: info.name, kex: info.kex };
    if (main.seen.group === group && main.seen.version === 0x0304) {
      groupSupport.push({ ...base, supported: true, evidence: 'negotiated in the main handshake' });
      continue;
    }
    if (!speaks13) {
      // Post-quantum groups are defined for TLS 1.3 only; there is nothing to ask a server that does not speak it.
      groupSupport.push({ ...base, supported: false, evidence: 'the server did not negotiate TLS 1.3' });
      continue;
    }
    if (unanswered >= 2) {
      groupSupport.push({ ...base, supported: undefined, evidence: 'not asked: the server stopped answering these questions' });
      continue;
    }
    progress(`Asking whether ${info.name} is supported`);
    const asked = await run(pinned, { id: `group-${group}`, purpose: `Offers only ${info.name}, with no key share, to see whether the server asks for one`, versions: ['1.3'], groups: [group], shareGroups: [], signatureSchemes: SIGNATURE_SCHEMES_WITH_PQ }, options);
    probes.push(asked.result);
    const { outcome } = asked.seen;
    if (outcome === 'hello-retry-request' && asked.seen.group === group) {
      groupSupport.push({ ...base, supported: true, evidence: `HelloRetryRequest selecting ${groupName(group)}` });
    } else if (outcome === 'alert') {
      groupSupport.push({ ...base, supported: false, evidence: `refused with alert ${asked.seen.alert?.name}` });
    } else {
      unanswered++;
      groupSupport.push({ ...base, supported: undefined, evidence: `no usable answer (${outcome}${asked.seen.detail ? `: ${asked.seen.detail}` : ''})` });
    }
  }

  const certificates = [main, classical, legacy].map((p) => p.seen.certificates).find((c) => c && c.length > 0) ?? [];
  return { probes, groupSupport, certificates, reachable: true };
}
