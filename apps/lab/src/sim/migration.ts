/**
 * The rules behind the migration simulator. Pure functions, no UI, so they are
 * easy to test and easy to explain.
 *
 * An app can sign users in only if all of these hold:
 *  1. The provider still publishes a key for the algorithm the app is assigned.
 *  2. The app's OIDC library can verify that algorithm.
 *  3. If the app stores the ID token in a cookie, the token fits (ML-DSA-65 doesn't).
 */

export type Alg = 'ES256' | 'ML-DSA-65';

export interface SimApp {
  id: string;
  name: string;
  /** Has the app's library been upgraded to verify ML-DSA? */
  libraryUpgraded: boolean;
  /** Does the app keep the whole ID token in a browser cookie? */
  tokenInCookie: boolean;
  /** Which algorithm the provider signs this app's ID tokens with. */
  alg: Alg;
}

export interface SimState {
  publishedKeys: Record<Alg, boolean>;
  apps: SimApp[];
}

export type AppStatus =
  | { ok: true; quantumSafe: boolean }
  | { ok: false; problem: 'no-key' | 'library' | 'cookie'; message: string };

const KEY_NAME: Record<Alg, string> = { ES256: 'old', 'ML-DSA-65': 'new' };

export function appStatus(app: SimApp, state: SimState): AppStatus {
  if (!state.publishedKeys[app.alg]) {
    return {
      ok: false,
      problem: 'no-key',
      message: `The login service doesn’t have the ${KEY_NAME[app.alg]} key, so it can’t sign this app’s logins.`,
    };
  }
  if (app.alg === 'ML-DSA-65' && !app.libraryUpgraded) {
    return {
      ok: false,
      problem: 'library',
      message: 'This app can’t read the new signature yet, so it turns everyone away.',
    };
  }
  if (app.alg === 'ML-DSA-65' && app.tokenInCookie) {
    return {
      ok: false,
      problem: 'cookie',
      message: 'The new token is too big for this app’s cookie. The browser drops it and users are signed straight back out.',
    };
  }
  return { ok: true, quantumSafe: app.alg === 'ML-DSA-65' };
}

export interface Summary {
  working: number;
  broken: number;
  quantumSafe: number;
  total: number;
  /** Done means every app is on ML-DSA-65, nothing is broken, and the classical key is retired. */
  done: boolean;
  nextStep: string;
}

export function summarize(state: SimState): Summary {
  const statuses = state.apps.map((app) => ({ app, status: appStatus(app, state) }));
  const working = statuses.filter((s) => s.status.ok).length;
  const quantumSafe = statuses.filter((s) => s.status.ok && s.status.quantumSafe).length;
  const total = state.apps.length;
  const done = quantumSafe === total && !state.publishedKeys.ES256;
  return { working, broken: total - working, quantumSafe, total, done, nextStep: nextStep(state, statuses) };
}

function nextStep(state: SimState, statuses: { app: SimApp; status: AppStatus }[]): string {
  const broken = statuses.find((s) => !s.status.ok);
  if (broken && !broken.status.ok) {
    const fix = {
      'no-key': `turn the ${KEY_NAME[broken.app.alg]} key back on, or move the app to a key the service still has.`,
      library: 'switch it back to the old signature, update it, then try again.',
      cookie: 'switch it back to the old signature and move its token out of the cookie first.',
    }[broken.status.problem];
    return `${broken.app.name} is locked out. To fix it, ${fix}`;
  }
  if (!state.publishedKeys['ML-DSA-65']) {
    return 'Start by adding the new key to the login service. The apps keep using the old one for now.';
  }
  const ready = state.apps.find((a) => a.alg === 'ES256' && a.libraryUpgraded && !a.tokenInCookie);
  if (ready) return `${ready.name} is ready. Switch it to the new signature.`;
  const notReady = state.apps.find((a) => a.alg === 'ES256');
  if (notReady) {
    const todo = !notReady.libraryUpgraded ? 'update it so it can read the new signature' : 'move its token out of the cookie';
    return `Get ${notReady.name} ready first: ${todo}.`;
  }
  if (state.publishedKeys.ES256) return 'Every app is on the new signature. Retire the old key.';
  return 'Done. No login here can be forged with a quantum computer.';
}

export const INITIAL_STATE: SimState = {
  publishedKeys: { ES256: true, 'ML-DSA-65': false },
  apps: [
    { id: 'payroll', name: 'Payroll', libraryUpgraded: false, tokenInCookie: true, alg: 'ES256' },
    { id: 'wiki', name: 'Team Wiki', libraryUpgraded: false, tokenInCookie: false, alg: 'ES256' },
    { id: 'expenses', name: 'Expenses', libraryUpgraded: true, tokenInCookie: true, alg: 'ES256' },
    { id: 'portal', name: 'Customer Portal', libraryUpgraded: true, tokenInCookie: false, alg: 'ES256' },
  ],
};

/** The safe order of operations, used by the "Show me" button. Each step returns a new state. */
export function safeSteps(start: SimState): SimState[] {
  const steps: SimState[] = [];
  let state = start;
  const push = (next: SimState) => {
    steps.push(next);
    state = next;
  };
  const updateApp = (id: string, change: Partial<SimApp>) =>
    push({ ...state, apps: state.apps.map((a) => (a.id === id ? { ...a, ...change } : a)) });

  if (!state.publishedKeys['ML-DSA-65']) push({ ...state, publishedKeys: { ...state.publishedKeys, 'ML-DSA-65': true } });
  for (const app of start.apps) {
    if (!app.libraryUpgraded) updateApp(app.id, { libraryUpgraded: true });
    if (app.tokenInCookie) updateApp(app.id, { tokenInCookie: false });
    if (app.alg !== 'ML-DSA-65') updateApp(app.id, { alg: 'ML-DSA-65' });
  }
  if (state.publishedKeys.ES256) push({ ...state, publishedKeys: { ...state.publishedKeys, ES256: false } });
  return steps;
}
