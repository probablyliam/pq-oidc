import { useEffect, useRef, useState } from 'react';
import type { DragEvent, KeyboardEvent } from 'react';
import { appStatus, INITIAL_STATE, safeSteps, summarize } from '../sim/migration.ts';
import type { SimApp, SimState } from '../sim/migration.ts';

/**
 * The migration as swapping parts. The login service and each app are built
 * from parts; the new parts sit in a tray. Drag one onto a matching slot (or
 * tap the part, then the slot). Fit the new signature before an app is ready
 * and its users are locked out: the order is the lesson.
 */
const STEP_DELAY_MS = 800;

type Part = 'pq-key' | 'reader' | 'storage' | 'pq-signature';
type Slot = { where: 'service' } | { where: 'app'; id: string; slot: 'reader' | 'storage' | 'signature' };

const PARTS: { id: Part; name: string; does: string }[] = [
  { id: 'pq-key', name: 'Quantum-proof key', does: 'for the login service' },
  { id: 'reader', name: 'Updated reader', does: 'lets an app check the new signature' },
  { id: 'storage', name: 'Server-side storage', does: 'keeps the token out of a cookie' },
  { id: 'pq-signature', name: 'Quantum-proof signature', does: 'replaces today’s signature on an app' },
];

/** Which part a slot takes, if it still holds the old one. */
function accepts(slot: Slot, state: SimState): Part | undefined {
  if (slot.where === 'service') return state.publishedKeys['ML-DSA-65'] ? undefined : 'pq-key';
  const app = state.apps.find((a) => a.id === slot.id);
  if (!app) return undefined;
  if (slot.slot === 'reader') return app.libraryUpgraded ? undefined : 'reader';
  if (slot.slot === 'storage') return app.tokenInCookie ? 'storage' : undefined;
  return app.alg === 'ES256' ? 'pq-signature' : undefined;
}

function fit(slot: Slot, state: SimState): SimState {
  if (slot.where === 'service') return { ...state, publishedKeys: { ...state.publishedKeys, 'ML-DSA-65': true } };
  const change: Partial<SimApp> =
    slot.slot === 'reader' ? { libraryUpgraded: true } : slot.slot === 'storage' ? { tokenInCookie: false } : { alg: 'ML-DSA-65' };
  return { ...state, apps: state.apps.map((a) => (a.id === slot.id ? { ...a, ...change } : a)) };
}

export function SwitchGame() {
  const [state, setState] = useState<SimState>(INITIAL_STATE);
  const [held, setHeld] = useState<Part>();
  const [playing, setPlaying] = useState(false);
  const timers = useRef<number[]>([]);
  const summary = summarize(state);

  useEffect(() => () => timers.current.forEach(window.clearTimeout), []);

  function place(slot: Slot, part: Part | undefined) {
    if (playing || !part || accepts(slot, state) !== part) return;
    setState((s) => fit(slot, s));
    setHeld(undefined);
  }

  /** Props for anything a part can be dropped on or tapped into. */
  function slotProps(slot: Slot) {
    const wanted = accepts(slot, state);
    const open = wanted !== undefined && held === wanted;
    return {
      className: `slot ${wanted ? 'old' : 'new'} ${open ? 'open' : ''}`,
      onDragOver: (e: DragEvent) => {
        if (open) e.preventDefault();
      },
      onDrop: (e: DragEvent) => {
        e.preventDefault();
        place(slot, e.dataTransfer.getData('text/plain') as Part);
      },
      onClick: () => place(slot, held),
      onKeyDown: (e: KeyboardEvent) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          place(slot, held);
        }
      },
    };
  }

  function showMe() {
    timers.current.forEach(window.clearTimeout);
    setHeld(undefined);
    setState(INITIAL_STATE);
    setPlaying(true);
    const steps = safeSteps(INITIAL_STATE);
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
    setHeld(undefined);
    setState(INITIAL_STATE);
  }

  const hasNew = state.publishedKeys['ML-DSA-65'];
  const hasOld = state.publishedKeys.ES256;
  const setOldKey = (on: boolean) => setState((s) => ({ ...s, publishedKeys: { ...s.publishedKeys, ES256: on } }));
  const switchBack = (id: string) =>
    setState((s) => ({ ...s, apps: s.apps.map((a) => (a.id === id ? { ...a, alg: 'ES256' as const } : a)) }));

  return (
    <section className="block" id="switch">
      <h2>Your turn: make the switch</h2>
      <p className="sub">Fit the new parts so all four apps are protected, without locking anyone out.</p>

      <div className="score" aria-live="polite">
        <div className="pips" role="img" aria-label={`${summary.quantumSafe} of 4 apps protected, ${summary.broken} locked out`}>
          {state.apps.map((app) => {
            const status = appStatus(app, state);
            return <i key={app.id} className={status.ok ? (status.quantumSafe ? 'safe' : '') : 'locked'} />;
          })}
        </div>
        <p>
          <b>{summary.quantumSafe} of 4 protected</b>
          {summary.broken > 0 && <b className="locked">, {summary.broken} locked out</b>}
          {summary.done && <b className="won">. Done.</b>}
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

      <div className="tray">
        <p className="tray-label">New parts. Drag one onto a slot, or tap it and then tap the slot.</p>
        <div className="parts">
          {PARTS.map((part) => (
            <button
              key={part.id}
              type="button"
              className="part"
              draggable={!playing}
              aria-pressed={held === part.id}
              disabled={playing}
              onDragStart={(e) => {
                e.dataTransfer.setData('text/plain', part.id);
                e.dataTransfer.effectAllowed = 'copy';
                setHeld(part.id);
              }}
              onDragEnd={() => setHeld(undefined)}
              onClick={() => setHeld((h) => (h === part.id ? undefined : part.id))}
            >
              <b>{part.name}</b>
              <span>{part.does}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="board">
        <article className="card service">
          <h3>Login service</h3>
          <div className="slots">
            <div className={`slot fixed ${hasOld ? 'old' : 'gone'}`}>
              <span className="slot-role">Signs with</span>
              <b>{hasOld ? 'Old key' : 'Old key, retired'}</b>
              {hasNew && (
                <button type="button" className="mini" disabled={playing} onClick={() => setOldKey(!hasOld)}>
                  {hasOld ? 'Retire it' : 'Bring it back'}
                </button>
              )}
            </div>
            <div {...slotProps({ where: 'service' })} role="button" tabIndex={0}>
              <span className="slot-role">And with</span>
              <b>{hasNew ? 'Quantum-proof key' : 'Empty: needs the quantum-proof key'}</b>
            </div>
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
              <div className="slots">
                <div {...slotProps({ where: 'app', id: app.id, slot: 'reader' })} role="button" tabIndex={0}>
                  <span className="slot-role">Checks signatures with</span>
                  <b>{app.libraryUpgraded ? 'Updated reader' : 'Old reader'}</b>
                </div>
                <div {...slotProps({ where: 'app', id: app.id, slot: 'storage' })} role="button" tabIndex={0}>
                  <span className="slot-role">Keeps the token in</span>
                  <b>{app.tokenInCookie ? 'A browser cookie' : 'Server-side storage'}</b>
                </div>
                <div {...slotProps({ where: 'app', id: app.id, slot: 'signature' })} role="button" tabIndex={0}>
                  <span className="slot-role">Receives</span>
                  <b>{switched ? 'Quantum-proof signature' : 'Today’s signature'}</b>
                  {switched && (
                    <button
                      type="button"
                      className="mini"
                      disabled={playing}
                      onClick={(e) => {
                        e.stopPropagation();
                        switchBack(app.id);
                      }}
                    >
                      Put the old one back
                    </button>
                  )}
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
