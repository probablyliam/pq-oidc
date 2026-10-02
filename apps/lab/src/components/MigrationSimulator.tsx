import { useEffect, useRef, useState } from 'react';
import { appStatus, INITIAL_STATE, safeSteps, summarize } from '../sim/migration.ts';
import type { Alg, SimApp, SimState } from '../sim/migration.ts';

const STEP_DELAY_MS = 850;
const SIGNATURE_LABEL: Record<Alg, string> = { ES256: 'Old signature', 'ML-DSA-65': 'New signature' };

export function MigrationSimulator() {
  const [state, setState] = useState<SimState>(INITIAL_STATE);
  const [playing, setPlaying] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  const summary = summarize(state);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  function updateApp(id: string, change: Partial<SimApp>) {
    setState((s) => ({ ...s, apps: s.apps.map((a) => (a.id === id ? { ...a, ...change } : a)) }));
  }

  function toggleKey(alg: Alg) {
    setState((s) => ({ ...s, publishedKeys: { ...s.publishedKeys, [alg]: !s.publishedKeys[alg] } }));
  }

  function playSafeOrder() {
    window.clearTimeout(timer.current);
    const steps = safeSteps(INITIAL_STATE);
    setState(INITIAL_STATE);
    setPlaying(true);
    steps.forEach((next, i) => {
      timer.current = window.setTimeout(
        () => {
          setState(next);
          if (i === steps.length - 1) setPlaying(false);
        },
        (i + 1) * STEP_DELAY_MS,
      );
    });
  }

  function reset() {
    window.clearTimeout(timer.current);
    setPlaying(false);
    setState(INITIAL_STATE);
  }

  return (
    <section className="step wide" id="switch">
      <h2>How do you switch without locking people out?</h2>
      <p className="lead">
        One app at a time. You run the login service for these four apps. Some aren’t ready: they can’t read the new
        signature yet, or they keep the token in a cookie. Switch one too early and its users can’t sign in.
      </p>

      <div className="sim">
        <div className="sim-status" aria-live="polite">
          <p className="sim-count">
            <b>
              {summary.quantumSafe} of {summary.total}
            </b>{' '}
            apps protected
            {summary.broken > 0 && (
              <>
                , <b className="locked">{summary.broken} locked out</b>
              </>
            )}
          </p>
          <p className="sim-next">{summary.nextStep}</p>
          <div className="sim-actions">
            <button type="button" className="primary" onClick={playSafeOrder} disabled={playing}>
              {playing ? 'Switching…' : 'Show me the safe order'}
            </button>
            <button type="button" onClick={reset}>
              Start over
            </button>
          </div>
        </div>

        <div className="sim-board">
          <div className="sim-service">
            <h3>Your login service</h3>
            <p>Keys it can sign with:</p>
            <label className="toggle">
              <input type="checkbox" checked={state.publishedKeys.ES256} onChange={() => toggleKey('ES256')} disabled={playing} />
              Old key
            </label>
            <label className="toggle">
              <input
                type="checkbox"
                checked={state.publishedKeys['ML-DSA-65']}
                onChange={() => toggleKey('ML-DSA-65')}
                disabled={playing}
              />
              New key
            </label>
          </div>

          {state.apps.map((app) => {
            const status = appStatus(app, state);
            const tone = status.ok ? (status.quantumSafe ? 'safe' : 'plain') : 'locked';
            return (
              <article key={app.id} className={`sim-app ${tone}`}>
                <header>
                  <h3>{app.name}</h3>
                  <span className="state">
                    {status.ok ? (status.quantumSafe ? 'Protected' : 'Working, forgeable') : 'Users locked out'}
                  </span>
                </header>
                <div className="pick" role="group" aria-label={`${app.name} signature`}>
                  {(['ES256', 'ML-DSA-65'] as const).map((alg) => (
                    <button
                      key={alg}
                      type="button"
                      aria-pressed={app.alg === alg}
                      disabled={playing}
                      onClick={() => updateApp(app.id, { alg })}
                    >
                      {SIGNATURE_LABEL[alg]}
                    </button>
                  ))}
                </div>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={app.libraryUpgraded}
                    disabled={playing}
                    onChange={(e) => updateApp(app.id, { libraryUpgraded: e.target.checked })}
                  />
                  Can read the new signature
                </label>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={!app.tokenInCookie}
                    disabled={playing}
                    onChange={(e) => updateApp(app.id, { tokenInCookie: !e.target.checked })}
                  />
                  Keeps the token out of cookies
                </label>
                {!status.ok && <p className="problem">{status.message}</p>}
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
