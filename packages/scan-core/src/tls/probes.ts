/**
 * The set of handshakes one scan performs, and why each exists:
 *
 *   pq-capable-client   what a client that supports post-quantum key exchange gets: hybrid offered first
 *   classical-client    what a client with no post-quantum support gets
 *   classical-kex-client  only when the certificate is post-quantum and the classical client got no
 *                       ServerHello: the same, but still offering ML-DSA signatures, so a refusal
 *                       can only be about the key exchange
 *   tls12-client        whether TLS 1.2 is still accepted, and its key exchange
 *   group-N             one per post-quantum group: does the server accept it at all?
 *
 *   classical-sig-client  the mirror of that: post-quantum groups, classical signatures only, to see
 *                       whether a classical certificate is still handed out
 *
 * Probes run one after another, each on its own connection to the pinned
 * address: around eight short handshakes per scan. A handshake whose
 * connection was cut is tried once more, since one cut connection shows nothing.
 */
import crypto from 'node:crypto';
import type { PinnedTarget } from '../net/resolve.ts';
import type { GroupSupport, ProbeId, ProbeResult } from '../report.ts';
import { summarizeCertificate } from '../x509/summary.ts';
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
    purpose: 'A client that supports post-quantum key exchange and ML-DSA signatures',
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

/**
 * The classical client leaves out post-quantum groups and ML-DSA signature schemes together. A server with a
 * post-quantum certificate refuses it for the signatures alone, whatever groups it accepts. This plan changes
 * the key exchange only.
 */
const CLASSICAL_KEX_PLAN: ProbePlan = {
  id: 'classical-kex-client',
  purpose: 'A client that accepts ML-DSA signatures but has no post-quantum key exchange',
  versions: ['1.3'],
  groups: CLASSICAL_GROUPS,
  shareGroups: [GROUP.x25519, GROUP.secp256r1],
  signatureSchemes: SIGNATURE_SCHEMES_WITH_PQ,
};

/**
 * And the other way round: the main handshake's groups, without ML-DSA. A server that holds a classical
 * certificate next to a post-quantum one hands the classical one to this client, even when it refuses every
 * handshake that lacks post-quantum key exchange.
 */
const CLASSICAL_SIG_PLAN: ProbePlan = {
  id: 'classical-sig-client',
  purpose: 'A client with post-quantum key exchange that accepts only classical signatures',
  versions: ['1.3'],
  groups: PLANS['pq-capable-client'].groups,
  shareGroups: PLANS['pq-capable-client'].shareGroups,
  signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL,
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

/** The kind of key a leaf certificate carries, or undefined when the bytes are not a certificate. */
function leafKey(der: Buffer): ProbeResult['leafKey'] {
  try {
    const { algorithm, family, quantumSafe } = summarizeCertificate(der, 0).key;
    return { algorithm, family, quantumSafe };
  } catch {
    return undefined;
  }
}

async function run(pinned: PinnedTarget, plan: ProbePlan, options: ObserveOptions): Promise<{ result: ProbeResult; seen: HandshakeObservation }> {
  const started = Date.now();
  let seen = await observeHandshake(pinned, toSpec(plan), options);
  let retried = false;
  // A connection cut with no TLS answer may be the server's way of refusing, or something in between. Ask once more.
  let confirmed: boolean | undefined;
  if (seen.outcome === 'closed') {
    const again = await observeHandshake(pinned, toSpec(plan), options);
    if (again.outcome === 'closed') confirmed = true;
    else if (again.outcome !== 'timeout' && again.outcome !== 'unreachable') seen = again;
  }
  // A HelloRetryRequest means "I support this group, send me a share for it". Do that, on a new connection.
  if (seen.outcome === 'hello-retry-request' && plan.shareGroups.length > 0 && seen.group !== undefined && canGenerateKeyShare(seen.group)) {
    seen = await observeHandshake(pinned, toSpec({ ...plan, shareGroups: [seen.group] }), options);
    retried = true;
  }
  const { certificates, alert, ...rest } = seen;
  const leaf = certificates?.[0];
  return {
    seen,
    result: {
      id: plan.id,
      purpose: plan.purpose,
      offered: { versions: plan.versions, groups: plan.groups, keyShares: plan.shareGroups },
      ...rest,
      alert: alert?.name,
      leafFingerprint: leaf ? crypto.createHash('sha256').update(leaf).digest('hex') : undefined,
      leafKey: leaf ? leafKey(leaf) : undefined,
      confirmed,
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

  if (main.result.leafKey?.quantumSafe && !['handshake', 'server-hello'].includes(classical.seen.outcome)) {
    progress('TLS handshake with classical key exchange and ML-DSA signatures');
    probes.push((await run(pinned, CLASSICAL_KEX_PLAN, options)).result);
  }

  if (main.result.leafKey?.quantumSafe && !classical.result.leafFingerprint && !legacy.result.leafFingerprint) {
    progress('TLS handshake with post-quantum key exchange and classical signatures');
    probes.push((await run(pinned, CLASSICAL_SIG_PLAN, options)).result);
  }

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
    } else if (outcome === 'closed' && asked.result.confirmed) {
      // Some stacks (Microsoft's front ends, for one) cut the connection instead of sending an alert when no offered group is usable.
      groupSupport.push({ ...base, supported: false, evidence: `refused: the connection was ${asked.seen.detail ? 'reset' : 'closed'} without a TLS alert, twice` });
    } else {
      unanswered++;
      groupSupport.push({ ...base, supported: undefined, evidence: `no usable answer (${outcome}${asked.seen.detail ? `: ${asked.seen.detail}` : ''})` });
    }
  }

  const certificates = [main, classical, legacy].map((p) => p.seen.certificates).find((c) => c && c.length > 0) ?? [];
  return { probes, groupSupport, certificates, reachable: true };
}
