import { useEffect, useRef, useState } from 'react';
import { appStatus, describeChanges, INITIAL_STATE, safeSteps, summarize } from '../sim/migration.ts';
import type { SimApp, SimState } from '../sim/migration.ts';

/**
 * Why the switch isn't one flick: a small company with one login service and
 * four apps that sign people in through it.
 *
 * Each app is a row; the three things that have to change are columns, always
 * in the same order (reader, token storage, signature). Old parts are grey,
 * new parts are blue. "Just switch everything today" shows what goes wrong;
 * then the reader does it cell by cell.
 */
const STEP_DELAY_MS = 900;

export function SwitchGame() {
  const [state, setState] = useState<SimState>(INITIAL_STATE);
  const [changes, setChanges] = useState(0);
  const [playing, setPlaying] = useState(false);
  const timers = useRef<number[]>([]);
  const summary = summarize(state);

  useEffect(() => () => timers.current.forEach(window.clearTimeout), []);

  function change(next: SimState) {
    setChanges((n) => n + describeChanges(state, next).length);
    setState(next);
  }
  const updateApp = (id: string, patch: Partial<SimApp>) =>
    change({ ...state, apps: state.apps.map((a) => (a.id === id ? { ...a, ...patch } : a)) });

  function reset() {
    timers.current.forEach(window.clearTimeout);
    setPlaying(false);
    setState(INITIAL_STATE);
    setChanges(0);
  }

  /** The tempting shortcut: new key in, every app switched, nothing prepared. */
  function flipEverything() {
    reset();
    const flipped: SimState = {
      publishedKeys: { ES256: true, 'ML-DSA-65': true },
      apps: INITIAL_STATE.apps.map((a) => ({ ...a, alg: 'ML-DSA-65' as const })),
    };
    setChanges(describeChanges(INITIAL_STATE, flipped).length);
    setState(flipped);
  }

  function showMe() {
    reset();
    setPlaying(true);
    const steps = safeSteps(INITIAL_STATE);
    timers.current = steps.map((next, i) =>
      window.setTimeout(
        () => {
          setChanges(i + 1);
          setState(next);
          if (i === steps.length - 1) setPlaying(false);
        },
        (i + 1) * STEP_DELAY_MS,
      ),
    );
  }

  const hasNew = state.publishedKeys['ML-DSA-65'];
  const hasOld = state.publishedKeys.ES256;

  return (
    <section className="block" id="switch">
      <h2>Your turn: why not just flip a switch?</h2>
      <p className="sub">
        A small company: one login service, and four apps that sign people in through it. Try switching everything at
        once, then do it properly.
      </p>

      <div className="switch-actions">
        <button type="button" className="danger" disabled={playing} onClick={flipEverything}>
          Just switch everything today
        </button>
        <button type="button" disabled={playing} onClick={showMe}>
          {playing ? 'Showing…' : 'Show me the right order'}
        </button>
        <button type="button" onClick={reset}>
          Start over
        </button>
        <p className="switch-score" aria-live="polite">
          <b>{summary.quantumSafe} of 4 apps protected</b>
          {summary.broken > 0 && <b className="locked">, {summary.broken} locked out</b>}
          {changes > 0 && <span>, {changes} {changes === 1 ? 'change' : 'changes'} made</span>}
        </p>
      </div>

      <div className="grid-board">
        <div className="service-row">
          <b>Login service</b>
          <span className="dep">signs logins with</span>
          <button
            type="button"
            className={`cell ${hasOld ? 'old' : 'gone'}`}
            disabled={playing || !hasNew}
            onClick={() => change({ ...state, publishedKeys: { ...state.publishedKeys, ES256: !hasOld } })}
          >
            <b>{hasOld ? 'Today’s key' : 'Today’s key, retired'}</b>
            <span>{!hasNew ? 'in use' : hasOld ? 'Retire it' : 'Bring it back'}</span>
          </button>
          <button
            type="button"
            className={`cell ${hasNew ? 'new' : 'empty'}`}
            disabled={playing || hasNew}
            onClick={() => change({ ...state, publishedKeys: { ...state.publishedKeys, 'ML-DSA-65': true } })}
          >
            <b>Quantum-proof key</b>
            <span>{hasNew ? 'added' : 'Add it'}</span>
          </button>
        </div>

        <p className="depends">Every app below depends on the login service, and has three things to change, left to right.</p>

        <div className="matrix" role="table">
          <div className="matrix-head" role="row">
            <span role="columnheader">App</span>
            <span role="columnheader">1. Reader</span>
            <span role="columnheader">2. Token storage</span>
            <span role="columnheader">3. Signature it receives</span>
            <span role="columnheader">Result</span>
          </div>
          {state.apps.map((app) => {
            const status = appStatus(app, state);
            const switched = app.alg === 'ML-DSA-65';
            const tone = status.ok ? (status.quantumSafe ? 'safe' : '') : 'locked';
            return (
              <div key={app.id} className={`matrix-row ${tone}`} role="row">
                <b role="cell">{app.name}</b>
                <button
                  type="button"
                  role="cell"
                  className={`cell ${app.libraryUpgraded ? 'new' : 'old'}`}
                  disabled={playing || app.libraryUpgraded}
                  onClick={() => updateApp(app.id, { libraryUpgraded: true })}
                >
                  <b>{app.libraryUpgraded ? 'Updated reader' : 'Old reader'}</b>
                  <span>{app.libraryUpgraded ? 'can check the new signature' : 'Update it'}</span>
                </button>
                <button
                  type="button"
                  role="cell"
                  className={`cell ${app.tokenInCookie ? 'old' : 'new'}`}
                  disabled={playing || !app.tokenInCookie}
                  onClick={() => updateApp(app.id, { tokenInCookie: false })}
                >
                  <b>{app.tokenInCookie ? 'Browser cookie' : 'On the server'}</b>
                  <span>{app.tokenInCookie ? 'Move it' : 'big tokens fit'}</span>
                </button>
                <button
                  type="button"
                  role="cell"
                  className={`cell ${switched ? 'new' : 'old'}`}
                  disabled={playing}
                  onClick={() => updateApp(app.id, { alg: switched ? 'ES256' : 'ML-DSA-65' })}
                >
                  <b>{switched ? 'Quantum-proof' : 'Today’s signature'}</b>
                  <span>{switched ? 'Switch back' : 'Switch it'}</span>
                </button>
                <p role="cell" className="result">
                  <b>{status.ok ? (status.quantumSafe ? 'Protected' : 'Working, forgeable') : 'Users locked out'}</b>
                  {!status.ok && <span>{status.message}</span>}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {summary.done && (
        <p className="switch-done">
          Done, and nobody was locked out: {changes} separate changes for four apps. Each one means changing software,
          testing it and releasing it, usually by a different team. That is why this takes companies years, not a day.
        </p>
      )}
    </section>
  );
}
