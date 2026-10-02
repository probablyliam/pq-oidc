import { describe, expect, it } from 'vitest';
import { actions, dependencies, INITIAL, inventory, NODES, safePlan, summarize, upgradeEverythingNow } from './system.ts';
import type { SystemState } from './system.ts';

const lookedAt: SystemState = { ...INITIAL, inventoried: NODES.map((n) => n.id) };
const status = (s: SystemState, id: string) => dependencies(s).find((d) => d.id === id)?.status;

describe('inventory comes first', () => {
  it('knows nothing about a part until it has been looked at', () => {
    expect(summarize(INITIAL).unknown).toBe(summarize(INITIAL).total);
    expect(actions(INITIAL).every((a) => a.blockedBy === 'Look at this part first.')).toBe(true);
  });

  it('looking at a part reveals its dependencies without protecting anything', () => {
    const s = inventory(INITIAL, 'auth');
    expect(status(s, 'token-signing')).toBe('legacy');
    expect(status(s, 'edge-key-exchange')).toBe('unknown');
  });
});

describe('actions have consequences', () => {
  it('signing ML-DSA tokens before the apps are ready breaks the web app and the API', () => {
    const s: SystemState = { ...lookedAt, authHasPqKey: true, tokenAlg: 'ML-DSA-65' };
    expect(status(s, 'webapp-reader')).toBe('broken');
    expect(status(s, 'webapp-storage')).toBe('broken');
    expect(status(s, 'api-reader')).toBe('broken');
  });

  it('the token switch is not available until the new key exists', () => {
    expect(actions(lookedAt).find((a) => a.id === 'auth-switch')?.blockedBy).toBe('Add the ML-DSA key first.');
  });

  it('hybrid key exchange protects the connection without breaking old browsers; PQ-only breaks them', () => {
    const hybrid: SystemState = { ...lookedAt, edgeHybrid: true };
    expect(status(hybrid, 'edge-key-exchange')).toBe('protected');
    expect(status(hybrid, 'old-browsers')).toBe('protected');
    expect(status({ ...hybrid, edgePqOnly: true }, 'old-browsers')).toBe('broken');
  });

  it('“upgrade everything now” causes four separate outages', () => {
    expect(summarize(upgradeEverythingNow()).broken).toBe(4);
  });
});

describe('some things are not yours to change', () => {
  it('the public certificate and the vendor stay blocked whatever you do', () => {
    const end = safePlan().at(-1)!;
    expect(status(end, 'edge-certificate')).toBe('blocked');
    expect(status(end, 'vendor-api')).toBe('blocked');
  });
});

describe('the safe plan', () => {
  it('never breaks anything and finishes with everything in your control protected', () => {
    const steps = safePlan();
    for (const step of steps) expect(summarize(step).broken).toBe(0);
    expect(summarize(steps.at(-1)!)).toMatchObject({ done: true, legacy: 0, blocked: 2, protectedCount: 8 });
  });
});
