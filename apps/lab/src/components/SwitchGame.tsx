import { useEffect, useRef, useState } from 'react';
import { appStatus, INITIAL_STATE, safeSteps, summarize } from '../sim/migration.ts';
import type { SimApp, SimState } from '../sim/migration.ts';

const STEP_DELAY_MS = 800;

/**
 * The migration as a small game: one goal, and buttons named after what they
 * do. Switching an app before it is ready locks its users out, which is the
 * lesson; the player finds the safe order by trying.
 */
export function SwitchGame() {
  const [state, setState] = useState<SimState>(INITIAL_STATE);
  const [playing, setPlaying] = useState(false);
  const timers = useRef<number[]>([]);
  const summary = summarize(state);

  useEffect(() => () => timers.current.forEach(window.clearTimeout), []);

  const updateApp = (id: string, change: Partial<SimApp>) =>
    setState((s) => ({ ...s, apps: s.apps.map((a) => (a.id === id ? { ...a, ...change } : a)) }));
  const setKey = (alg: 'ES256' | 'ML-DSA-65', on: boolean) =>
    setState((s) => ({ ...s, publishedKeys: { ...s.publishedKeys, [alg]: on } }));

  function showMe() {
    timers.current.forEach(window.clearTimeout);
    const steps = safeSteps(INITIAL_STATE);
    setState(INITIAL_STATE);
    setPlaying(true);
    timers.current = steps.map((next, i) =>
      window.setTimeout(
        () => {
          setState(next);
          if (i === steps.length - 1) setPlaying(false);
        },
        (i + 1) * STEP_DELAY_MS,
      ),
    );
  }

  function startOver() {
    timers.current.forEach(window.clearTimeout);
    setPlaying(false);
    setState(INITIAL_STATE);
  }

  const hasNew = state.publishedKeys['ML-DSA-65'];
  const hasOld = state.publishedKeys.ES256;

  return (
    <section className="block" id="switch">
      <h2>Your turn: make the switch</h2>
      <p className="sub">
        Protect all four apps and retire the old key, without locking anyone out.
      </p>

      <div className="score" aria-live="polite">
        <div className="pips" role="img" aria-label={`${summary.quantumSafe} of ${summary.total} apps protected, ${summary.broken} locked out`}>
          {state.apps.map((app) => {
            const status = appStatus(app, state);
            return <i key={app.id} className={status.ok ? (status.quantumSafe ? 'safe' : '') : 'locked'} />;
          })}
        </div>
        <p>
          <b>{summary.quantumSafe} of 4 protected</b>
          {summary.broken > 0 && <b className="locked">, {summary.broken} locked out</b>}
          {summary.done && <b className="won">. Done: no login here can be forged with a quantum computer.</b>}
        </p>
        <div className="score-actions">
          <button type="button" onClick={showMe} disabled={playing}>
            {playing ? 'Showing…' : 'Show me how'}
          </button>
          <button type="button" onClick={startOver}>
            Start over
          </button>
        </div>
      </div>

      <div className="board">
        <article className="card service">
          <h3>Login service</h3>
          <ul className="has">
            <li className={hasOld ? 'on' : 'off'}>Old key {hasOld ? 'in use' : 'retired'}</li>
            <li className={hasNew ? 'on' : 'off'}>{hasNew ? 'Quantum-proof key added' : 'No quantum-proof key yet'}</li>
          </ul>
          <div className="card-actions">
            {!hasNew ? (
              <button type="button" className="primary" disabled={playing} onClick={() => setKey('ML-DSA-65', true)}>
                Add the quantum-proof key
              </button>
            ) : (
              <button type="button" disabled={playing} onClick={() => setKey('ES256', !hasOld)}>
                {hasOld ? 'Retire the old key' : 'Bring the old key back'}
              </button>
            )}
          </div>
        </article>

        {state.apps.map((app) => {
          const status = appStatus(app, state);
          const tone = status.ok ? (status.quantumSafe ? 'safe' : '') : 'locked';
          const switched = app.alg === 'ML-DSA-65';
          return (
            <article key={app.id} className={`card ${tone}`}>
              <h3>{app.name}</h3>
              <p className="card-state">
                {status.ok ? (status.quantumSafe ? 'Protected' : 'Working, but logins can be forged') : 'Users locked out'}
              </p>
              {!status.ok && <p className="card-why">{status.message}</p>}
              <ul className="has">
                <li className={app.libraryUpgraded ? 'on' : 'off'}>
                  {app.libraryUpgraded ? 'Can read the new signature' : 'Can’t read the new signature yet'}
                </li>
                <li className={app.tokenInCookie ? 'off' : 'on'}>
                  {app.tokenInCookie ? 'Keeps the login token in a cookie' : 'Keeps the token out of cookies'}
                </li>
              </ul>
              <div className="card-actions">
                {!app.libraryUpgraded && (
                  <button type="button" disabled={playing} onClick={() => updateApp(app.id, { libraryUpgraded: true })}>
                    Update the app
                  </button>
                )}
                {app.tokenInCookie && (
                  <button type="button" disabled={playing} onClick={() => updateApp(app.id, { tokenInCookie: false })}>
                    Stop using the cookie
                  </button>
                )}
                <button
                  type="button"
                  className={switched ? '' : 'primary'}
                  disabled={playing}
                  onClick={() => updateApp(app.id, { alg: switched ? 'ES256' : 'ML-DSA-65' })}
                >
                  {switched ? 'Switch back' : 'Switch to the new signature'}
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
