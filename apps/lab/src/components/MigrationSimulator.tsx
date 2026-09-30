import { useEffect, useRef, useState } from 'react';
import { appStatus, INITIAL_STATE, safeSteps, summarize } from '../sim/migration.ts';
import type { Alg, SimApp, SimState } from '../sim/migration.ts';

const STEP_DELAY_MS = 850;

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

  const pct = (n: number) => `${(n / summary.total) * 100}%`;

  return (
    <section className="chapter wrap" id="migrate">
      <div className="chapter-head">
        <h2>Move four apps to post-quantum signatures without logging anyone out</h2>
        <p>
          You run the identity provider. Each app below gets its ID tokens signed with the algorithm you pick. Some
          apps aren’t ready: their library can’t verify ML-DSA yet, or they keep the token in a cookie. Switch an app
          too early and its users can’t sign in. Try it, or watch the safe order.
        </p>
      </div>

      <div className="migration">
        <div className="panel sim-summary">
          <div className="progress">
            <div className="progress-track" aria-hidden="true">
              <span className="safe" style={{ width: pct(summary.quantumSafe) }} />
              <span className="broken" style={{ width: pct(summary.broken) }} />
            </div>
            <div className="small" aria-live="polite">
              <b>
                {summary.quantumSafe} of {summary.total}
              </b>{' '}
              apps quantum-safe ·{' '}
              {summary.broken > 0 ? (
                <b style={{ color: 'var(--bad)' }}>{summary.broken} broken</b>
              ) : (
                <span>nothing broken</span>
              )}
            </div>
            <p className="next-step small">{summary.nextStep}</p>
          </div>
          <div className="actions" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn" type="button" onClick={playSafeOrder} disabled={playing}>
              {playing ? 'Migrating…' : 'Show me the safe order'}
            </button>
            <button className="btn ghost" type="button" onClick={reset}>
              Reset
            </button>
          </div>
        </div>

        <div className="sim-grid">
          <div className="provider-card">
            <div>
              <span className="eyebrow">Identity provider</span>
              <h3>Published signing keys</h3>
              <p className="small muted">Apps can only get tokens signed with a key that is published in the JWKS.</p>
            </div>
            <div className="key-row">
              <span className="badge classical">ES256 · classical</span>
              <label className="switch">
                <input
                  type="checkbox"
                  checked={state.publishedKeys.ES256}
                  onChange={() => toggleKey('ES256')}
                  disabled={playing}
                  aria-label="Publish the ES256 key"
                />
              </label>
            </div>
            <div className="key-row">
              <span className="badge pq">ML-DSA-65 · post-quantum</span>
              <label className="switch">
                <input
                  type="checkbox"
                  checked={state.publishedKeys['ML-DSA-65']}
                  onChange={() => toggleKey('ML-DSA-65')}
                  disabled={playing}
                  aria-label="Publish the ML-DSA-65 key"
                />
              </label>
            </div>
            {summary.done && (
              <div className="callout good small">
                <b>Done.</b> Every login is signed with ML-DSA-65 and the classical key is retired.
              </div>
            )}
          </div>

          <div className="apps">
            {state.apps.map((app) => {
              const status = appStatus(app, state);
              const cls = status.ok ? (status.quantumSafe ? 'safe' : '') : 'broken';
              return (
                <article key={app.id} className={`app-card ${cls}`}>
                  <header>
                    <h3>{app.name}</h3>
                    {status.ok ? (
                      status.quantumSafe ? (
                        <span className="badge pq">quantum-safe</span>
                      ) : (
                        <span className="badge neutral">working</span>
                      )
                    ) : (
                      <span className="badge bad">can’t sign in</span>
                    )}
                  </header>
                  <div className="segmented" role="group" aria-label={`${app.name} signing algorithm`}>
                    {(['ES256', 'ML-DSA-65'] as const).map((alg) => (
                      <button
                        key={alg}
                        type="button"
                        className={alg === 'ES256' ? 'classical' : 'pq'}
                        aria-pressed={app.alg === alg}
                        disabled={playing}
                        onClick={() => updateApp(app.id, { alg })}
                      >
                        {alg}
                      </button>
                    ))}
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={app.libraryUpgraded}
                      disabled={playing}
                      onChange={(e) => updateApp(app.id, { libraryUpgraded: e.target.checked })}
                    />
                    Library supports ML-DSA
                  </label>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={!app.tokenInCookie}
                      disabled={playing}
                      onChange={(e) => updateApp(app.id, { tokenInCookie: !e.target.checked })}
                    />
                    Server-side sessions
                  </label>
                  {!status.ok && <p className="problem">{status.message}</p>}
                </article>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
