/**
 * "Migrate a real system": a small company's login path and the cryptography
 * each part depends on. Pure functions, so the rules can be tested and read.
 *
 *   Browsers ─► Load balancer ─► Web app ─► Internal API
 *                                  │
 *                                  ├─► Auth service
 *                                  └─► Payment provider (third party)
 *
 * The lesson is in the dependencies: some parts can change on their own, some
 * must change in a particular order, and some are not the company's to change.
 */

export type NodeId = 'browsers' | 'balancer' | 'webapp' | 'auth' | 'api' | 'vendor';
export type Status = 'unknown' | 'legacy' | 'protected' | 'broken' | 'blocked';

export interface SystemState {
  /** Nodes whose cryptography has been looked at. Nothing can be changed before that. */
  inventoried: NodeId[];
  /** Load balancer offers hybrid key exchange (old browsers fall back to classical). */
  edgeHybrid: boolean;
  /** Load balancer refuses anything but post-quantum key exchange. */
  edgePqOnly: boolean;
  internalHybrid: boolean;
  authHasPqKey: boolean;
  tokenAlg: 'ES256' | 'ML-DSA-65';
  legacyKeyRetired: boolean;
  webAppReadsPq: boolean;
  webAppTokenInCookie: boolean;
  apiReadsPq: boolean;
  vendorAsked: boolean;
}

export const INITIAL: SystemState = {
  inventoried: [],
  edgeHybrid: false,
  edgePqOnly: false,
  internalHybrid: false,
  authHasPqKey: false,
  tokenAlg: 'ES256',
  legacyKeyRetired: false,
  webAppReadsPq: false,
  webAppTokenInCookie: true,
  apiReadsPq: false,
  vendorAsked: false,
};

export const NODES: { id: NodeId; name: string; role: string }[] = [
  { id: 'browsers', name: 'Browsers', role: 'your users’ devices' },
  { id: 'balancer', name: 'Load balancer', role: 'where HTTPS ends' },
  { id: 'webapp', name: 'Web app', role: 'what users log in to' },
  { id: 'auth', name: 'Auth service', role: 'signs login tokens' },
  { id: 'api', name: 'Internal API', role: 'trusts those tokens' },
  { id: 'vendor', name: 'Payment provider', role: 'a third party' },
];

export interface Dependency {
  id: string;
  node: NodeId;
  /** What the cryptography is for. */
  what: string;
  /** What is in use right now. */
  uses: string;
  status: Status;
  /** Why it is broken or blocked, when it is. */
  problem?: string;
}

export function dependencies(s: SystemState): Dependency[] {
  const pqTokens = s.tokenAlg === 'ML-DSA-65';
  const deps: Dependency[] = [
    {
      id: 'old-browsers',
      node: 'browsers',
      what: 'Connecting to you',
      uses: s.edgePqOnly ? 'Post-quantum only' : s.edgeHybrid ? 'Hybrid where supported; older browsers still connect' : 'Classical key exchange',
      status: s.edgePqOnly ? 'broken' : s.edgeHybrid ? 'protected' : 'legacy',
      problem: s.edgePqOnly ? 'Older browsers and devices can’t do post-quantum key exchange, so they can’t connect at all.' : undefined,
    },
    {
      id: 'edge-key-exchange',
      node: 'balancer',
      what: 'Connection secret (key exchange)',
      uses: s.edgePqOnly ? 'ML-KEM only' : s.edgeHybrid ? 'ECDHE + ML-KEM (hybrid)' : 'ECDHE',
      status: s.edgeHybrid || s.edgePqOnly ? 'protected' : 'legacy',
    },
    {
      id: 'edge-certificate',
      node: 'balancer',
      what: 'Proving your site’s identity (certificate)',
      uses: 'ECDSA certificate',
      status: 'blocked',
      problem: 'Public certificate authorities don’t issue post-quantum certificates that browsers accept yet. You can’t fix this one alone.',
    },
    {
      id: 'webapp-reader',
      node: 'webapp',
      what: 'Checking login tokens',
      uses: s.webAppReadsPq ? 'Library that reads ES256 and ML-DSA' : 'Library that only reads ES256',
      status: pqTokens && !s.webAppReadsPq ? 'broken' : pqTokens ? 'protected' : 'legacy',
      problem: pqTokens && !s.webAppReadsPq ? 'The web app can’t read ML-DSA tokens. Nobody can log in.' : undefined,
    },
    {
      id: 'webapp-storage',
      node: 'webapp',
      what: 'Keeping the login token',
      uses: s.webAppTokenInCookie ? 'Browser cookie (4,096 bytes)' : 'Server-side session',
      status: pqTokens && s.webAppTokenInCookie ? 'broken' : s.webAppTokenInCookie ? 'legacy' : 'protected',
      problem: pqTokens && s.webAppTokenInCookie ? 'The ML-DSA token is too big for the cookie. Browsers drop it and users are logged straight back out.' : undefined,
    },
    {
      id: 'token-signing',
      node: 'auth',
      what: 'Signing login tokens',
      uses: pqTokens ? 'ML-DSA-65' : s.authHasPqKey ? 'ES256 (ML-DSA key ready)' : 'ES256',
      status: pqTokens ? 'protected' : 'legacy',
    },
    {
      id: 'legacy-key',
      node: 'auth',
      what: 'Old signing key',
      uses: s.legacyKeyRetired ? 'Retired' : 'ES256 key still trusted',
      status: s.legacyKeyRetired ? 'protected' : 'legacy',
    },
    {
      id: 'api-reader',
      node: 'api',
      what: 'Checking login tokens',
      uses: s.apiReadsPq ? 'Library that reads ES256 and ML-DSA' : 'Library that only reads ES256',
      status: pqTokens && !s.apiReadsPq ? 'broken' : pqTokens ? 'protected' : 'legacy',
      problem: pqTokens && !s.apiReadsPq ? 'The internal API rejects ML-DSA tokens. Every request behind the login fails.' : undefined,
    },
    {
      id: 'internal-key-exchange',
      node: 'api',
      what: 'Connections between your own services',
      uses: s.internalHybrid ? 'ECDHE + ML-KEM (hybrid)' : 'ECDHE',
      status: s.internalHybrid ? 'protected' : 'legacy',
    },
    {
      id: 'vendor-api',
      node: 'vendor',
      what: 'Their API’s cryptography',
      uses: s.vendorAsked ? 'Classical; “on the roadmap”' : 'Unknown',
      status: 'blocked',
      problem: 'It’s their system. You can ask, put it in the contract, and wait.',
    },
  ];
  // Until a node has been looked at, nobody knows what it depends on.
  return deps.map((d) => (s.inventoried.includes(d.node) ? d : { ...d, uses: 'Not looked at yet', status: 'unknown', problem: undefined }));
}

export interface Action {
  id: string;
  node: NodeId;
  label: string;
  /** Why it can't be done right now, if it can't. */
  blockedBy?: string;
  apply: (s: SystemState) => SystemState;
}

export function actions(s: SystemState): Action[] {
  const all: Action[] = [
    { id: 'edge-hybrid', node: 'balancer', label: 'Offer hybrid key exchange', apply: (x) => ({ ...x, edgeHybrid: true }) },
    {
      id: 'edge-pq-only',
      node: 'balancer',
      label: s.edgePqOnly ? 'Accept classical connections again' : 'Refuse anything but post-quantum',
      apply: (x) => ({ ...x, edgePqOnly: !x.edgePqOnly, edgeHybrid: true }),
    },
    { id: 'webapp-library', node: 'webapp', label: 'Update the token library', apply: (x) => ({ ...x, webAppReadsPq: true }) },
    { id: 'webapp-storage', node: 'webapp', label: 'Move tokens out of the cookie', apply: (x) => ({ ...x, webAppTokenInCookie: false }) },
    { id: 'auth-add-key', node: 'auth', label: 'Add an ML-DSA key next to the old one', apply: (x) => ({ ...x, authHasPqKey: true }) },
    {
      id: 'auth-switch',
      node: 'auth',
      label: s.tokenAlg === 'ML-DSA-65' ? 'Go back to signing with ES256' : 'Sign tokens with ML-DSA',
      blockedBy: s.authHasPqKey ? undefined : 'Add the ML-DSA key first.',
      apply: (x) => ({ ...x, tokenAlg: x.tokenAlg === 'ML-DSA-65' ? 'ES256' : 'ML-DSA-65', legacyKeyRetired: false }),
    },
    {
      id: 'auth-retire',
      node: 'auth',
      label: 'Retire the old ES256 key',
      blockedBy: s.tokenAlg === 'ML-DSA-65' ? undefined : 'Tokens are still signed with it.',
      apply: (x) => ({ ...x, legacyKeyRetired: true }),
    },
    { id: 'api-library', node: 'api', label: 'Update the token library', apply: (x) => ({ ...x, apiReadsPq: true }) },
    { id: 'api-hybrid', node: 'api', label: 'Use hybrid key exchange internally', apply: (x) => ({ ...x, internalHybrid: true }) },
    { id: 'vendor-ask', node: 'vendor', label: 'Ask them for their plan', apply: (x) => ({ ...x, vendorAsked: true }) },
  ];
  const done: Record<string, boolean> = {
    'edge-hybrid': s.edgeHybrid,
    'webapp-library': s.webAppReadsPq,
    'webapp-storage': !s.webAppTokenInCookie,
    'auth-add-key': s.authHasPqKey,
    'auth-retire': s.legacyKeyRetired,
    'api-library': s.apiReadsPq,
    'api-hybrid': s.internalHybrid,
    'vendor-ask': s.vendorAsked,
  };
  return all
    .filter((a) => !done[a.id])
    .map((a) => (s.inventoried.includes(a.node) ? a : { ...a, blockedBy: 'Look at this part first.' }));
}

export function inventory(s: SystemState, node: NodeId): SystemState {
  return s.inventoried.includes(node) ? s : { ...s, inventoried: [...s.inventoried, node] };
}

/** The tempting shortcut: switch everything on tonight, with no inventory and no preparation. */
export function upgradeEverythingNow(): SystemState {
  return {
    ...INITIAL,
    inventoried: NODES.map((n) => n.id),
    edgeHybrid: true,
    edgePqOnly: true,
    internalHybrid: true,
    authHasPqKey: true,
    tokenAlg: 'ML-DSA-65',
    vendorAsked: true,
  };
}

export interface Summary {
  total: number;
  /** Counts of dependencies in each state; they add up to `total`. */
  protectedCount: number;
  legacy: number;
  broken: number;
  blocked: number;
  unknown: number;
  /** Everything the company controls is protected and nothing is broken. */
  done: boolean;
}

export function summarize(s: SystemState): Summary {
  const deps = dependencies(s);
  const count = (status: Status) => deps.filter((d) => d.status === status).length;
  const summary = {
    total: deps.length,
    protectedCount: count('protected'),
    legacy: count('legacy'),
    broken: count('broken'),
    blocked: count('blocked'),
    unknown: count('unknown'),
  };
  return { ...summary, done: summary.legacy === 0 && summary.broken === 0 && summary.unknown === 0 };
}

/** One safe order of work, for the "show me" button. */
export function safePlan(): SystemState[] {
  const steps: SystemState[] = [];
  let s = INITIAL;
  const push = (next: SystemState) => {
    steps.push(next);
    s = next;
  };
  for (const node of NODES) push(inventory(s, node.id));
  for (const id of ['edge-hybrid', 'api-hybrid', 'vendor-ask', 'auth-add-key', 'webapp-library', 'webapp-storage', 'api-library', 'auth-switch', 'auth-retire']) {
    const action = actions(s).find((a) => a.id === id);
    if (!action || action.blockedBy) throw new Error(`Safe plan can't do "${id}"`);
    push(action.apply(s));
  }
  return steps;
}
