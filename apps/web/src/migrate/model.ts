/**
 * A small company's sign-in path, as a migration problem.
 *
 *   Clients ─► Load balancer ─► Web app ─┬─► Auth service
 *                                        ├─► Internal API ─► Database
 *                                        └─► Payment provider (someone else's)
 *
 * Each part uses cryptography for something, and the parts depend on each
 * other: a change that is right for one can break another. The model is pure
 * functions over a state, so the rules can be read and tested:
 *
 *   uses(state)       what each part uses, and how it stands
 *   problems(state)   what is broken in production right now
 *   actions(state)    what can be changed, and what blocks each change
 *   rehearse(state,a) what a change would break, found in staging instead
 *
 * Nothing here is random and nothing is scored.
 */
import type { ScanReport } from '@pq-oidc/scan-core/report';

export type PartId = 'clients' | 'edge' | 'webapp' | 'auth' | 'api' | 'database' | 'vendor';

export interface Part {
  id: PartId;
  name: string;
  role: string;
  /** Whether the company can change it. */
  yours: boolean;
}

export const PARTS: Part[] = [
  { id: 'clients', name: 'Clients', role: 'browsers, your mobile app, a partner’s batch job', yours: false },
  { id: 'edge', name: 'Load balancer', role: 'where TLS ends', yours: true },
  { id: 'webapp', name: 'Web app', role: 'what people sign in to', yours: true },
  { id: 'auth', name: 'Auth service', role: 'signs the tokens', yours: true },
  { id: 'api', name: 'Internal API', role: 'trusts those tokens', yours: true },
  { id: 'database', name: 'Database', role: 'and its backups', yours: true },
  { id: 'vendor', name: 'Payment provider', role: 'a third party', yours: false },
];

export interface State {
  /** Parts whose cryptography has been looked at. Nothing can be changed before that. */
  looked: PartId[];
  edge: 'classical' | 'hybrid-offered' | 'hybrid-required';
  appShipped: boolean;
  partnerAsked: boolean;
  /** What the auth service publishes: the old key, both, or only the new one. */
  keys: 'classical' | 'both' | 'pq';
  /** Which signature each audience's tokens carry. Switching one app at a time is the rollout. */
  signing: { webapp: 'classical' | 'pq'; api: 'classical' | 'pq' };
  webappLibrary: boolean;
  webappSession: boolean;
  apiLibrary: boolean;
  dbEngine: boolean;
  dbTls: boolean;
  backupsRewrapped: boolean;
  vendorAsked: boolean;
  /** Changes that were tried in staging. */
  rehearsed: string[];
  /** Changes that reached production and broke something there. */
  incidents: string[];
  /** What a scan observed, when the exercise starts from one. */
  seen?: { host: string; keyExchange: string; certificate: string; tokens?: string };
}

export const INITIAL: State = {
  looked: [],
  edge: 'classical',
  appShipped: false,
  partnerAsked: false,
  keys: 'classical',
  signing: { webapp: 'classical', api: 'classical' },
  webappLibrary: false,
  webappSession: false,
  apiLibrary: false,
  dbEngine: false,
  dbTls: false,
  backupsRewrapped: false,
  vendorAsked: false,
  rehearsed: [],
  incidents: [],
};

export type Standing =
  /** Not looked at yet. */
  | 'unknown'
  /** In use and breakable by a quantum computer. */
  | 'exposed'
  | 'protected'
  /** Protected for some, exposed for others. */
  | 'partial'
  /** Down in production. */
  | 'broken'
  /** Cannot be changed by this company. */
  | 'waiting';

export interface Use {
  id: string;
  part: PartId;
  /** What the cryptography is for. */
  purpose: string;
  /** What is in use right now. */
  now: string;
  standing: Standing;
  /** Why it stands that way, when that needs saying. */
  note?: string;
}

export interface Problem {
  id: string;
  part: PartId;
  /** What users experience. */
  text: string;
  /** The change that undoes it. */
  undo: string;
}

/** What is broken in production in this state. */
export function problems(s: State): Problem[] {
  const out: Problem[] = [];
  if (s.edge === 'hybrid-required') {
    out.push({
      id: 'old-clients',
      part: 'clients',
      text: 'The partner’s batch job cannot connect at all, and neither can anyone on an old version of your mobile app. Their TLS libraries have no ML-KEM.',
      undo: 'edge-allow-classical',
    });
  }
  if (s.keys !== 'classical' && !s.apiLibrary) {
    out.push({
      id: 'api-keyset',
      part: 'api',
      text: 'The internal API is down. Its token library cannot parse a key set that contains a key type it has never heard of, even though it only needs the old key.',
      undo: s.keys === 'both' ? 'auth-remove-key' : 'api-library',
    });
  }
  if (s.signing.webapp === 'pq' && !s.webappLibrary) {
    out.push({ id: 'webapp-verify', part: 'webapp', text: 'Nobody can sign in. The web app’s library does not know ML-DSA and rejects every token.', undo: 'auth-sign-webapp' });
  } else if (s.signing.webapp === 'pq' && !s.webappSession) {
    out.push({
      id: 'webapp-cookie',
      part: 'webapp',
      text: 'People sign in and are signed out again at once. The ML-DSA token is too big for the cookie it is kept in, and browsers drop an oversized cookie without an error.',
      undo: 'auth-sign-webapp',
    });
  }
  if (s.signing.api === 'pq' && !s.apiLibrary) {
    out.push({ id: 'api-verify', part: 'api', text: 'Every request behind the login fails. The internal API’s library rejects ML-DSA tokens.', undo: 'auth-sign-api' });
  }
  return out;
}

export function uses(s: State): Use[] {
  const broken = new Set(problems(s).map((p) => p.id));
  const seen = s.seen;
  const list: Use[] = [
    {
      id: 'clients-support',
      part: 'clients',
      purpose: 'Which key exchange each client can do',
      now: s.appShipped ? 'Browsers: hybrid. Mobile app: hybrid once people update. Partner job: classical only' : 'Browsers: hybrid. Mobile app: classical only. Partner job: classical only',
      standing: broken.has('old-clients') ? 'broken' : 'waiting',
      note: 'You control one of the three: your own app, and even then only after people install the update.',
    },
    {
      id: 'edge-kex',
      part: 'edge',
      purpose: 'Key exchange',
      now: s.edge === 'classical' ? (seen?.keyExchange ?? 'X25519 only') : s.edge === 'hybrid-offered' ? 'X25519MLKEM768 offered, classical still accepted' : 'X25519MLKEM768 required',
      standing: s.edge === 'classical' ? 'exposed' : s.edge === 'hybrid-offered' ? 'partial' : 'protected',
      note:
        s.edge === 'classical'
          ? 'Traffic recorded today can be decrypted later.'
          : s.edge === 'hybrid-offered'
            ? 'Clients that can do hybrid are protected. The ones that cannot still connect, and their traffic can still be recorded and decrypted later.'
            : undefined,
    },
    {
      id: 'edge-certificate',
      part: 'edge',
      purpose: 'Certificate',
      now: seen?.certificate ?? 'ECDSA P-256',
      standing: 'waiting',
      note: 'Public certificate authorities do not issue post-quantum certificates yet. Nothing to do here but keep certificate lifetimes short.',
    },
    {
      id: 'webapp-library',
      part: 'webapp',
      purpose: 'Checking tokens',
      now: s.webappLibrary ? 'Library that reads ES256 and ML-DSA' : 'Library that only reads ES256',
      standing: broken.has('webapp-verify') ? 'broken' : s.signing.webapp === 'pq' ? 'protected' : 'exposed',
    },
    {
      id: 'webapp-storage',
      part: 'webapp',
      purpose: 'Where the token is kept',
      now: s.webappSession ? 'On the server; the cookie holds a session ID' : 'In a browser cookie (4,096 bytes at most)',
      standing: broken.has('webapp-cookie') ? 'broken' : s.webappSession ? 'protected' : 'exposed',
      note: s.webappSession ? undefined : 'Not a cryptographic weakness in itself: it is what stops the token from growing.',
    },
    {
      id: 'auth-keys',
      part: 'auth',
      purpose: 'Published signing keys',
      now: s.keys === 'classical' ? (seen?.tokens ?? 'One ES256 key') : s.keys === 'both' ? 'An ES256 key and an ML-DSA-65 key' : 'One ML-DSA-65 key',
      standing: s.keys === 'pq' ? 'protected' : 'exposed',
      note: s.keys === 'both' ? 'While the old key is published, a token forged with it is still accepted.' : undefined,
    },
    {
      id: 'auth-signing',
      part: 'auth',
      purpose: 'What tokens are signed with',
      now: `Web app: ${s.signing.webapp === 'pq' ? 'ML-DSA-65' : 'ES256'}. Internal API: ${s.signing.api === 'pq' ? 'ML-DSA-65' : 'ES256'}`,
      standing: s.signing.webapp === 'pq' && s.signing.api === 'pq' ? 'protected' : s.signing.webapp === 'pq' || s.signing.api === 'pq' ? 'partial' : 'exposed',
    },
    {
      id: 'api-library',
      part: 'api',
      purpose: 'Checking tokens',
      now: s.apiLibrary ? 'Library that reads ES256 and ML-DSA' : 'Library that only reads ES256',
      standing: broken.has('api-keyset') || broken.has('api-verify') ? 'broken' : s.signing.api === 'pq' ? 'protected' : 'exposed',
    },
    {
      id: 'db-tls',
      part: 'database',
      purpose: 'Connection from the API',
      now: s.dbTls ? 'TLS with hybrid key exchange' : s.dbEngine ? 'TLS with classical key exchange (hybrid available)' : 'TLS with classical key exchange; this engine version has no hybrid',
      standing: s.dbTls ? 'protected' : 'exposed',
    },
    {
      id: 'db-backups',
      part: 'database',
      purpose: 'Backup encryption',
      now: s.backupsRewrapped ? 'AES-256, with the key wrapped by ML-KEM' : 'AES-256, with the key wrapped by RSA-2048',
      standing: s.backupsRewrapped ? 'partial' : 'exposed',
      note: s.backupsRewrapped
        ? 'New backups are protected. Copies of old backups that already left the building stay as they were made.'
        : 'AES is fine. The RSA wrapping is not: whoever holds a copy of a backup can unwrap its key later.',
    },
    {
      id: 'vendor-api',
      part: 'vendor',
      purpose: 'Their API and the webhooks they sign',
      now: s.vendorAsked ? 'Classical TLS and RSA signatures. “On the roadmap for next year.”' : 'Classical TLS and RSA signatures',
      standing: 'waiting',
      note: 'It is their system. You can ask, write it into the contract, and plan around their date.',
    },
  ];
  // Until a part has been looked at, nobody knows what it uses.
  return list.map((use) => (s.looked.includes(use.part) ? use : { ...use, now: 'Not looked at yet', standing: 'unknown', note: undefined }));
}

export interface Change {
  id: string;
  part: PartId;
  label: string;
  /** Why it cannot be done right now. */
  blockedBy?: string;
  /** Cannot be reversed once done. */
  final?: boolean;
  apply: (s: State) => State;
}

/** Every change that makes sense in this state, including the ones that are blocked. */
export function changes(s: State): Change[] {
  const all: (Change & { hidden?: boolean })[] = [
    { id: 'ship-app', part: 'clients', label: 'Ship a mobile app update whose TLS library supports hybrid', hidden: s.appShipped, apply: (x) => ({ ...x, appShipped: true }) },
    { id: 'ask-partner', part: 'clients', label: 'Ask the partner when their client will support hybrid', hidden: s.partnerAsked, apply: (x) => ({ ...x, partnerAsked: true }) },
    { id: 'edge-offer-hybrid', part: 'edge', label: 'Offer hybrid key exchange, keep accepting classical', hidden: s.edge !== 'classical', apply: (x) => ({ ...x, edge: 'hybrid-offered' }) },
    { id: 'edge-require-hybrid', part: 'edge', label: 'Refuse clients that cannot do hybrid', hidden: s.edge === 'hybrid-required', apply: (x) => ({ ...x, edge: 'hybrid-required' }) },
    { id: 'edge-allow-classical', part: 'edge', label: 'Accept classical clients again', hidden: s.edge !== 'hybrid-required', apply: (x) => ({ ...x, edge: 'hybrid-offered' }) },
    { id: 'webapp-library', part: 'webapp', label: 'Upgrade the token library', hidden: s.webappLibrary, apply: (x) => ({ ...x, webappLibrary: true }) },
    { id: 'webapp-session', part: 'webapp', label: 'Keep the token on the server instead of in a cookie', hidden: s.webappSession, apply: (x) => ({ ...x, webappSession: true }) },
    { id: 'auth-add-key', part: 'auth', label: 'Publish an ML-DSA-65 key next to the old one', hidden: s.keys !== 'classical', apply: (x) => ({ ...x, keys: 'both' }) },
    {
      id: 'auth-remove-key',
      part: 'auth',
      label: 'Take the ML-DSA-65 key back out of the key set',
      hidden: s.keys !== 'both',
      blockedBy: s.signing.webapp === 'pq' || s.signing.api === 'pq' ? 'Tokens are being signed with it. Switch those back first.' : undefined,
      apply: (x) => ({ ...x, keys: 'classical' }),
    },
    {
      id: 'auth-sign-webapp',
      part: 'auth',
      label: s.signing.webapp === 'pq' ? 'Go back to ES256 for the web app' : 'Sign the web app’s tokens with ML-DSA-65',
      blockedBy: s.keys === 'classical' ? 'There is no ML-DSA key yet.' : s.keys === 'pq' ? 'The old key is gone. There is nothing to go back to.' : undefined,
      apply: (x) => ({ ...x, signing: { ...x.signing, webapp: x.signing.webapp === 'pq' ? 'classical' : 'pq' } }),
    },
    {
      id: 'auth-sign-api',
      part: 'auth',
      label: s.signing.api === 'pq' ? 'Go back to ES256 for the internal API' : 'Sign the internal API’s tokens with ML-DSA-65',
      blockedBy: s.keys === 'classical' ? 'There is no ML-DSA key yet.' : s.keys === 'pq' ? 'The old key is gone. There is nothing to go back to.' : undefined,
      apply: (x) => ({ ...x, signing: { ...x.signing, api: x.signing.api === 'pq' ? 'classical' : 'pq' } }),
    },
    {
      id: 'auth-retire',
      part: 'auth',
      label: 'Retire the ES256 key',
      hidden: s.keys === 'pq',
      final: true,
      blockedBy: s.keys === 'classical' ? 'It is the only key.' : s.signing.webapp !== 'pq' || s.signing.api !== 'pq' ? 'Some tokens are still signed with it.' : undefined,
      apply: (x) => ({ ...x, keys: 'pq' }),
    },
    { id: 'api-library', part: 'api', label: 'Upgrade the token library', hidden: s.apiLibrary, apply: (x) => ({ ...x, apiLibrary: true }) },
    { id: 'db-engine', part: 'database', label: 'Upgrade the database engine (a maintenance window)', hidden: s.dbEngine, apply: (x) => ({ ...x, dbEngine: true }) },
    {
      id: 'db-tls',
      part: 'database',
      label: 'Use hybrid key exchange between the API and the database',
      hidden: s.dbTls,
      blockedBy: s.dbEngine ? undefined : 'This engine version cannot do it. Upgrade the engine first.',
      apply: (x) => ({ ...x, dbTls: true }),
    },
    { id: 'db-rewrap', part: 'database', label: 'Wrap backup keys with ML-KEM from now on', hidden: s.backupsRewrapped, apply: (x) => ({ ...x, backupsRewrapped: true }) },
    { id: 'ask-vendor', part: 'vendor', label: 'Ask the provider for their plan and date', hidden: s.vendorAsked, apply: (x) => ({ ...x, vendorAsked: true }) },
  ];
  return all.filter((change) => !change.hidden).map(({ hidden: _hidden, ...change }) => (s.looked.includes(change.part) ? change : { ...change, blockedBy: 'Look at this part first.' }));
}

export function look(s: State, part: PartId): State {
  return s.looked.includes(part) ? s : { ...s, looked: [...s.looked, part] };
}

/** Tries a change in staging: returns what it would break, without breaking it. */
export function rehearse(s: State, id: string): { state: State; wouldBreak: Problem[] } {
  const change = changes(s).find((c) => c.id === id);
  if (!change || change.blockedBy) return { state: s, wouldBreak: [] };
  const before = new Set(problems(s).map((p) => p.id));
  const wouldBreak = problems(change.apply(s)).filter((p) => !before.has(p.id));
  return { state: { ...s, rehearsed: s.rehearsed.includes(id) ? s.rehearsed : [...s.rehearsed, id] }, wouldBreak };
}

/** Makes a change in production. If it breaks something that staging was never asked about, that is recorded. */
export function rollOut(s: State, id: string): State {
  const change = changes(s).find((c) => c.id === id);
  if (!change || change.blockedBy) return s;
  const before = new Set(problems(s).map((p) => p.id));
  const next = change.apply(s);
  const brokeSomething = problems(next).some((p) => !before.has(p.id));
  return brokeSomething && !s.rehearsed.includes(id) && !s.incidents.includes(id) ? { ...next, incidents: [...next.incidents, id] } : next;
}

export interface Summary {
  counts: Record<Standing, number>;
  /** Everything the company can change is changed, and nothing is broken. */
  done: boolean;
  /** What stays exposed at the end, and whose move it is. */
  remaining: string[];
}

export function summarize(s: State): Summary {
  const list = uses(s);
  const counts: Record<Standing, number> = { unknown: 0, exposed: 0, protected: 0, partial: 0, broken: 0, waiting: 0 };
  for (const use of list) counts[use.standing]++;
  const done =
    counts.unknown === 0 && counts.broken === 0 && counts.exposed === 0 && s.keys === 'pq' && s.edge !== 'classical' && s.appShipped && s.partnerAsked && s.vendorAsked && s.backupsRewrapped;
  const remaining = [
    'Clients that cannot do hybrid key exchange still connect with classical. Their traffic stays exposed until they upgrade, and the partner’s job is not yours to upgrade.',
    'The certificate is still ECDSA, because no public authority issues anything else yet.',
    'Backups copied before the change are wrapped with RSA forever.',
    'The payment provider moves on its own schedule.',
  ];
  return { counts, done, remaining };
}

/** One order of work that never breaks production. */
export const SAFE_ORDER: string[] = [
  'look:edge',
  'look:clients',
  'look:webapp',
  'look:auth',
  'look:api',
  'look:database',
  'look:vendor',
  'edge-offer-hybrid',
  'ship-app',
  'ask-partner',
  'ask-vendor',
  'db-rewrap',
  'db-engine',
  'db-tls',
  'api-library',
  'webapp-library',
  'webapp-session',
  'auth-add-key',
  'auth-sign-webapp',
  'auth-sign-api',
  'auth-retire',
];

/** The next step of the safe order that has not been done, if any. */
export function nextSafeStep(s: State): string | undefined {
  const available = new Set(changes(s).filter((c) => !c.blockedBy).map((c) => c.id));
  return SAFE_ORDER.find((step) => (step.startsWith('look:') ? !s.looked.includes(step.slice(5) as PartId) : available.has(step) && isForward(s, step)));
}

/** Toggles appear in both directions; only the forward direction is part of the plan. */
function isForward(s: State, id: string): boolean {
  if (id === 'auth-sign-webapp') return s.signing.webapp === 'classical';
  if (id === 'auth-sign-api') return s.signing.api === 'classical';
  return true;
}

export function step(s: State, id: string): State {
  return id.startsWith('look:') ? look(s, id.slice(5) as PartId) : rollOut(s, id);
}

/**
 * Starts the exercise from a real scan. A scan sees the edge of a system: its
 * key exchange, its certificate, and its token signing if that is published.
 * Those parts start already looked at, with what the scan observed. Everything
 * behind the edge starts unknown, which is exactly what an outside scan cannot see.
 */
export function seedFromScan(report: ScanReport): State {
  const layer = (id: string) => report.layers.find((l) => l.id === id);
  const kex = layer('key-establishment');
  const tokens = layer('token-signing');
  const edge: State['edge'] = kex?.exposure === 'no-known-attack' ? 'hybrid-required' : kex?.exposure === 'depends-on-client' ? 'hybrid-offered' : 'classical';
  const tokensSeen = tokens !== undefined && tokens.exposure !== 'undetermined';
  return {
    ...INITIAL,
    looked: tokensSeen ? ['edge', 'auth'] : ['edge'],
    edge,
    seen: {
      host: report.target.hostname,
      keyExchange: (kex?.headline ?? 'unknown').replace(/^(Classical|Hybrid|Post-quantum): /, ''),
      certificate: (layer('server-authentication')?.headline ?? 'unknown').replace(/^(Classical|Post-quantum): /, '').replace(/ certificate$/, ''),
      tokens: tokensSeen ? tokens.headline.replace(/^(Classical|Migrating|Post-quantum): /, '') : undefined,
    },
  };
}
