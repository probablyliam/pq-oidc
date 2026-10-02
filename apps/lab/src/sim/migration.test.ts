import { describe, expect, it } from 'vitest';
import { appStatus, describeChanges, INITIAL_STATE, phase, safeSteps, summarize } from './migration.ts';
import type { SimApp, SimState } from './migration.ts';

const withApp = (change: Partial<SimApp>): SimState => ({
  publishedKeys: { ES256: true, 'ML-DSA-65': true },
  apps: [{ id: 'a', name: 'App', libraryUpgraded: true, tokenInCookie: false, alg: 'ES256', ...change }],
});

describe('appStatus', () => {
  it('works on ES256 today, but is not quantum-safe', () => {
    const state = withApp({});
    expect(appStatus(state.apps[0]!, state)).toEqual({ ok: true, quantumSafe: false });
  });

  it('breaks when switched to ML-DSA-65 before the library is upgraded', () => {
    const state = withApp({ alg: 'ML-DSA-65', libraryUpgraded: false });
    expect(appStatus(state.apps[0]!, state)).toMatchObject({ ok: false, problem: 'library' });
  });

  it('breaks when switched to ML-DSA-65 while the token lives in a cookie', () => {
    const state = withApp({ alg: 'ML-DSA-65', tokenInCookie: true });
    expect(appStatus(state.apps[0]!, state)).toMatchObject({ ok: false, problem: 'cookie' });
  });

  it('breaks when its key is retired too early', () => {
    const state: SimState = { ...withApp({}), publishedKeys: { ES256: false, 'ML-DSA-65': true } };
    expect(appStatus(state.apps[0]!, state)).toMatchObject({ ok: false, problem: 'no-key' });
  });

  it('is quantum-safe on ML-DSA-65 once the app is ready', () => {
    const state = withApp({ alg: 'ML-DSA-65' });
    expect(appStatus(state.apps[0]!, state)).toEqual({ ok: true, quantumSafe: true });
  });
});

describe('the migration as a whole', () => {
  it('starts with everything working and nothing quantum-safe', () => {
    expect(summarize(INITIAL_STATE)).toMatchObject({ working: 4, broken: 0, quantumSafe: 0, done: false });
    expect(summarize(INITIAL_STATE).nextStep).toContain('adding the new key');
  });

  it('follows a safe order in which no app ever breaks', () => {
    const steps = safeSteps(INITIAL_STATE);
    for (const state of steps) expect(summarize(state).broken).toBe(0);
    const end = summarize(steps.at(-1)!);
    expect(end).toMatchObject({ quantumSafe: 4, done: true });
    expect(end.nextStep).toContain('Done.');
  });
});

describe('the recommended order', () => {
  it('moves through the phases in order and logs one line per change', () => {
    const steps = safeSteps(INITIAL_STATE);
    const phases = [phase(INITIAL_STATE), ...steps.map(phase)];
    expect(phases[0]).toBe(1);
    expect(phases.at(-1)).toBe(5);
    expect([...phases].sort((a, b) => a - b).at(-1)).toBe(5);

    let previous = INITIAL_STATE;
    const log: string[] = [];
    for (const step of steps) {
      log.push(...describeChanges(previous, step));
      previous = step;
    }
    expect(log).toHaveLength(steps.length);
    expect(log[0]).toBe('Login service: added the quantum-proof key');
    expect(log.at(-1)).toBe('Login service: retired the old key');
  });
});
