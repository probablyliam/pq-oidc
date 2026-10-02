import { describe, expect, it } from 'vitest';
import type { ScanReport } from '@pq-oidc/scan-core/report';
import github from '../recorded/github.json' with { type: 'json' };
import google from '../recorded/google.json' with { type: 'json' };
import labPq from '../recorded/lab-pq.json' with { type: 'json' };
import { changes, INITIAL, look, nextSafeStep, PARTS, problems, rehearse, rollOut, SAFE_ORDER, seedFromScan, step, summarize, uses } from './model.ts';
import type { State } from './model.ts';

const inventoried = PARTS.reduce((state, part) => look(state, part.id), INITIAL);
const after = (state: State, ...ids: string[]) => ids.reduce(step, state);
const broken = (state: State) => problems(state).map((p) => p.id);

describe('inventory comes first', () => {
  it('nothing is known and nothing can be changed until a part has been looked at', () => {
    expect(uses(INITIAL).every((use) => use.standing === 'unknown' && use.now === 'Not looked at yet')).toBe(true);
    expect(changes(INITIAL).every((change) => change.blockedBy === 'Look at this part first.')).toBe(true);
    expect(rollOut(INITIAL, 'edge-offer-hybrid')).toBe(INITIAL);
  });

  it('looking at one part reveals that part only', () => {
    const state = look(INITIAL, 'edge');
    expect(uses(state).filter((use) => use.standing !== 'unknown').map((use) => use.part)).toEqual(['edge', 'edge']);
    expect(changes(state).filter((change) => !change.blockedBy).map((change) => change.id)).toEqual(['edge-offer-hybrid', 'edge-require-hybrid']);
  });
});

describe('a change that is right for one part can break another', () => {
  it('requiring hybrid key exchange locks out clients the company does not control', () => {
    const state = after(inventoried, 'edge-require-hybrid');
    expect(broken(state)).toEqual(['old-clients']);
    expect(uses(state).find((use) => use.id === 'clients-support')?.standing).toBe('broken');
    // Offering it while still accepting classical breaks nobody, and going back is one change.
    expect(broken(after(inventoried, 'edge-offer-hybrid'))).toEqual([]);
    expect(broken(after(state, 'edge-allow-classical'))).toEqual([]);
  });

  it('merely publishing a new key takes the internal API down: a dependency nobody had written down', () => {
    const state = after(inventoried, 'auth-add-key');
    expect(state.signing).toEqual({ webapp: 'classical', api: 'classical' }); // no token changed
    expect(broken(state)).toEqual(['api-keyset']);
    expect(broken(after(state, 'auth-remove-key'))).toEqual([]);
    expect(broken(after(inventoried, 'api-library', 'auth-add-key'))).toEqual([]);
  });

  it('switching an app’s tokens before the app is ready breaks sign-in, in two different ways', () => {
    const ready = after(inventoried, 'api-library', 'auth-add-key');
    expect(broken(after(ready, 'auth-sign-webapp'))).toEqual(['webapp-verify']);
    // The library is upgraded but the token still lives in a cookie: it no longer fits.
    expect(broken(after(ready, 'webapp-library', 'auth-sign-webapp'))).toEqual(['webapp-cookie']);
    expect(broken(after(ready, 'webapp-library', 'webapp-session', 'auth-sign-webapp'))).toEqual([]);
  });

  it('each app is switched separately, so one can go back without touching the other', () => {
    const state = after(inventoried, 'api-library', 'webapp-library', 'webapp-session', 'auth-add-key', 'auth-sign-webapp', 'auth-sign-api');
    expect(state.signing).toEqual({ webapp: 'pq', api: 'pq' });
    expect(after(state, 'auth-sign-webapp').signing).toEqual({ webapp: 'classical', api: 'pq' });
  });

  it('blocks a change whose prerequisite is missing, and says why', () => {
    const blocked = (state: State, id: string) => changes(state).find((change) => change.id === id)?.blockedBy;
    expect(blocked(inventoried, 'auth-sign-webapp')).toBe('There is no ML-DSA key yet.');
    expect(blocked(inventoried, 'db-tls')).toMatch(/Upgrade the engine first/);
    expect(blocked(inventoried, 'auth-retire')).toBe('It is the only key.');
    expect(blocked(after(inventoried, 'api-library', 'auth-add-key'), 'auth-retire')).toBe('Some tokens are still signed with it.');
    expect(after(inventoried, 'db-tls').dbTls).toBe(false);
  });
});

describe('testing before rolling out', () => {
  it('a staging run shows what would break without breaking it', () => {
    const { state, wouldBreak } = rehearse(inventoried, 'auth-add-key');
    expect(wouldBreak.map((p) => p.id)).toEqual(['api-keyset']);
    expect(broken(state)).toEqual([]);
    expect(state.keys).toBe('classical');
    expect(state.rehearsed).toEqual(['auth-add-key']);
    expect(rehearse(inventoried, 'edge-offer-hybrid').wouldBreak).toEqual([]);
  });

  it('records an incident only when production was the first place a break was seen', () => {
    expect(after(inventoried, 'auth-add-key').incidents).toEqual(['auth-add-key']);
    // Rehearsed first: it still breaks if rolled out anyway, but it is not a surprise.
    const rehearsed = rehearse(inventoried, 'auth-add-key').state;
    expect(broken(rollOut(rehearsed, 'auth-add-key'))).toEqual(['api-keyset']);
    expect(rollOut(rehearsed, 'auth-add-key').incidents).toEqual([]);
    // A change that breaks nothing is never an incident.
    expect(after(inventoried, 'edge-offer-hybrid').incidents).toEqual([]);
  });
});

describe('decommissioning', () => {
  const migrated = after(inventoried, 'api-library', 'webapp-library', 'webapp-session', 'auth-add-key', 'auth-sign-webapp', 'auth-sign-api');

  it('while the old key is published, the key set is still exposed', () => {
    expect(uses(migrated).find((use) => use.id === 'auth-keys')).toMatchObject({ standing: 'exposed', note: expect.stringContaining('still accepted') });
  });

  it('retiring the old key is final: afterwards there is nothing to roll back to', () => {
    const retire = changes(migrated).find((change) => change.id === 'auth-retire');
    expect(retire).toMatchObject({ final: true, blockedBy: undefined });
    const retired = after(migrated, 'auth-retire');
    expect(retired.keys).toBe('pq');
    expect(changes(retired).find((change) => change.id === 'auth-sign-webapp')?.blockedBy).toMatch(/nothing to go back to/);
    expect(after(retired, 'auth-sign-webapp').signing.webapp).toBe('pq');
  });
});

describe('one safe order', () => {
  it('never breaks production and ends with everything the company controls changed', () => {
    let state = INITIAL;
    for (const id of SAFE_ORDER) {
      const next = step(state, id);
      expect(next, `${id} did something`).not.toBe(state);
      expect(broken(next), `after ${id}`).toEqual([]);
      state = next;
    }
    expect(state.incidents).toEqual([]);
    const summary = summarize(state);
    expect(summary.done).toBe(true);
    expect(summary.counts).toMatchObject({ unknown: 0, exposed: 0, broken: 0 });
  });

  it('can be followed one step at a time from anywhere, including after a mistake is undone', () => {
    let state = after(inventoried, 'edge-require-hybrid', 'edge-allow-classical');
    for (let i = 0; i < 40; i++) {
      const next = nextSafeStep(state);
      if (!next) break;
      state = step(state, next);
    }
    expect(summarize(state).done).toBe(true);
    expect(nextSafeStep(state)).toBeUndefined();
  });

  it('is honest about what is left at the end', () => {
    const state = SAFE_ORDER.reduce(step, INITIAL);
    const standing = Object.fromEntries(uses(state).map((use) => [use.id, use.standing]));
    // Not everything turns green: some of it is someone else's, and some exposure cannot be undone.
    expect(standing).toMatchObject({ 'edge-kex': 'partial', 'edge-certificate': 'waiting', 'clients-support': 'waiting', 'vendor-api': 'waiting', 'db-backups': 'partial', 'auth-keys': 'protected' });
    expect(summarize(state).remaining).toHaveLength(4);
  });

  it('is not done while anything the company controls is still exposed', () => {
    const almost = SAFE_ORDER.filter((id) => id !== 'auth-retire').reduce(step, INITIAL);
    expect(summarize(almost).done).toBe(false);
  });
});

describe('starting from a real scan', () => {
  it('a scan that saw hybrid key exchange and RSA tokens: the edge and the token keys are known, the rest is not', () => {
    const state = seedFromScan(google as unknown as ScanReport);
    expect(state.looked).toEqual(['edge', 'auth']);
    expect(state.edge).toBe('hybrid-offered');
    expect(state.seen).toMatchObject({ host: 'accounts.google.com', keyExchange: 'X25519MLKEM768, with classical fallback', certificate: 'ECDSA P-256', tokens: 'RSA 2048-bit' });
    const known = uses(state).filter((use) => use.standing !== 'unknown').map((use) => use.id);
    expect(known).toEqual(['edge-kex', 'edge-certificate', 'auth-keys', 'auth-signing']);
    expect(uses(state).find((use) => use.id === 'auth-keys')?.now).toBe('RSA 2048-bit');
  });

  it('a scan that could not see token signing leaves the auth service unknown', () => {
    const state = seedFromScan(github as unknown as ScanReport);
    expect(state.looked).toEqual(['edge']);
    expect(state.edge).toBe('classical');
    expect(state.seen?.tokens).toBeUndefined();
    expect(uses(state).find((use) => use.id === 'edge-kex')).toMatchObject({ now: 'x25519', standing: 'exposed' });
  });

  it('a system that already signs with ML-DSA starts with that work done', () => {
    const state = seedFromScan(labPq as unknown as ScanReport);
    expect(state).toMatchObject({ edge: 'hybrid-required', keys: 'pq', signing: { webapp: 'pq', api: 'pq' }, apiLibrary: true, webappLibrary: true, webappSession: true });
    expect(broken(state).filter((id) => id !== 'old-clients')).toEqual([]);
  });
});
