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

export function appStatus(app: SimApp, state: SimState): AppStatus {
  if (!state.publishedKeys[app.alg]) {
    return {
      ok: false,
      problem: 'no-key',
      message: `The provider doesn't publish a ${app.alg} key, so it can't sign tokens for this app.`,
    };
  }
  if (app.alg === 'ML-DSA-65' && !app.libraryUpgraded) {
    return {
      ok: false,
      problem: 'library',
      message: "The app's library rejects ML-DSA-65 tokens: “this app only accepts ES256”.",
    };
  }
  if (app.alg === 'ML-DSA-65' && app.tokenInCookie) {
    return {
      ok: false,
      problem: 'cookie',
      message: 'The ~4.9 KB token no longer fits in a cookie. The browser drops it and users get logged out.',
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
      'no-key': `Publish the ${broken.app.alg} key, or move ${broken.app.name} to a key that is published.`,
      library: `Switch ${broken.app.name} back to ES256, upgrade its library, then try again.`,
      cookie: `Switch ${broken.app.name} back to ES256 and move it to server-side sessions first.`,
    }[broken.status.problem];
    return `Fix ${broken.app.name}: ${fix}`;
  }
  if (!state.publishedKeys['ML-DSA-65']) {
    return 'Phase 1: publish the ML-DSA-65 key next to the ES256 key. Nothing changes for apps yet.';
  }
  const notReady = state.apps.find((a) => a.alg === 'ES256' && (!a.libraryUpgraded || a.tokenInCookie));
  const ready = state.apps.find((a) => a.alg === 'ES256' && a.libraryUpgraded && !a.tokenInCookie);
  if (ready) return `Phase 2: ${ready.name} is ready. Switch it to ML-DSA-65.`;
  if (notReady) {
    const todo = !notReady.libraryUpgraded ? 'upgrade its library' : 'move it to server-side sessions';
    return `Phase 2: prepare ${notReady.name} first: ${todo}.`;
  }
  if (state.publishedKeys.ES256) return 'Phase 3: every app is on ML-DSA-65. Retire the ES256 key.';
  return 'Migration complete: every login is signed with a post-quantum key.';
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
