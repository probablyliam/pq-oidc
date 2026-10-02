import { useEffect, useState } from 'react';
import { actions, dependencies, INITIAL, inventory, NODES, safePlan, summarize, upgradeEverythingNow } from '../sim/system.ts';
import type { Dependency, NodeId, Status, SystemState } from '../sim/system.ts';
import { useSequence } from '../lab/useSequence.ts';

const STATUS: Record<Status, string> = {
  unknown: 'Not looked at',
  legacy: 'Quantum-breakable',
  protected: 'Protected',
  broken: 'Broken',
  blocked: 'Not yours to change',
};
const METER_ORDER: Status[] = ['protected', 'legacy', 'broken', 'blocked', 'unknown'];
const PLAN = safePlan();

const TAKEAWAYS = [
  ['Find it first.', 'Nothing could be changed until you had looked at what each part uses.'],
  ['Readers before signers.', 'Every app had to understand the new signature before the auth service started using it.'],
  ['Hybrid keeps everyone connected.', 'Old browsers kept working because the old key exchange stayed on offer next to the new one.'],
  ['Remove the old key last.', 'Until it is retired, a forged token signed with it is still accepted.'],
  ['Some of it isn’t yours.', 'The public certificate and the payment provider are waiting on other people.'],
];

function NodeCard({
  id,
  state,
  deps,
  onChange,
}: {
  id: NodeId;
  state: SystemState;
  deps: Dependency[];
  onChange: (next: SystemState) => void;
}) {
  const node = NODES.find((n) => n.id === id)!;
  const looked = state.inventoried.includes(id);
  const worst = (['broken', 'legacy', 'blocked', 'protected'] as const).find((s) => deps.some((d) => d.status === s));
  return (
    <article className={`node ${looked ? worst : 'unknown'}`}>
      <header>
        <b>{node.name}</b>
        <span>{node.role}</span>
      </header>
      {looked ? (
        <>
          <ul className="deps">
            {deps.map((d) => (
              <li key={d.id} className={d.status}>
                <span className="dep-what">{d.what}</span>
                <b>{d.uses}</b>
                <span className="dep-status">{STATUS[d.status]}</span>
                {d.problem && <p>{d.problem}</p>}
              </li>
            ))}
          </ul>
          <div className="node-actions">
            {actions(state)
              .filter((a) => a.node === id)
              .map((a) => (
                <button key={a.id} type="button" disabled={Boolean(a.blockedBy)} title={a.blockedBy} onClick={() => onChange(a.apply(state))}>
                  {a.label}
                  {a.blockedBy && <small>{a.blockedBy}</small>}
                </button>
              ))}
          </div>
        </>
      ) : (
        <button type="button" className="primary" onClick={() => onChange(inventory(state, id))}>
          Look at what it uses
        </button>
      )}
    </article>
  );
}

/** A small company's login path. You can only change what you have looked at, and every change has consequences. */
export function Migrate() {
  const [state, setState] = useState<SystemState>(INITIAL);
  const plan = useSequence(PLAN.length, 1100);

  // While the safe order is playing, the system is whatever step the player is on.
  useEffect(() => {
    if (plan.index > 0) setState(PLAN[plan.index - 1]!);
  }, [plan.index]);

  const deps = dependencies(state);
  const summary = summarize(state);
  const byNode = (id: NodeId) => deps.filter((d) => d.node === id);
  const change = (next: SystemState) => {
    plan.reset();
    setState(next);
  };
  const card = (id: NodeId) => <NodeCard id={id} state={state} deps={byNode(id)} onChange={change} />;
  const counts: Record<Status, number> = {
    protected: summary.protectedCount,
    legacy: summary.legacy,
    broken: summary.broken,
    blocked: summary.blocked,
    unknown: summary.unknown,
  };

  return (
    <section className="block" id="migrate">
      <h2>Migrate a real system</h2>
      <p className="sub">
        One company’s login path. Ten places use cryptography, and you don’t know what any of them use yet. Make all of
        it quantum-safe without locking anyone out.
      </p>

      <div className="migrate-bar">
        <div className="meter" role="img" aria-label={METER_ORDER.map((s) => `${counts[s]} ${STATUS[s]}`).join(', ')}>
          {METER_ORDER.flatMap((s) => Array.from({ length: counts[s] }, (_, i) => <i key={`${s}-${i}`} className={s} />))}
        </div>
        <ul className="meter-key">
          {METER_ORDER.filter((s) => counts[s] > 0).map((s) => (
            <li key={s} className={s}>
              {counts[s]} {STATUS[s].toLowerCase()}
            </li>
          ))}
        </ul>
        <div className="migrate-actions">
          <button type="button" className="danger" onClick={() => change(upgradeEverythingNow())}>
            Upgrade everything tonight
          </button>
          <button type="button" onClick={plan.start} disabled={plan.playing}>
            {plan.playing ? `Step ${plan.index} of ${PLAN.length}` : 'Show a safe order'}
          </button>
          <button type="button" className="link" onClick={() => change(INITIAL)}>
            Start over
          </button>
        </div>
      </div>

      {summary.broken > 0 && (
        <p className="outage" role="status">
          {summary.broken} {summary.broken === 1 ? 'thing is' : 'things are'} broken. Real users are locked out until you fix or undo it.
        </p>
      )}

      <div className="system">
        <div className="path">
          {card('browsers')}
          {card('balancer')}
          {card('webapp')}
        </div>
        <p className="relies">The web app relies on</p>
        <div className="path behind">
          {card('auth')}
          {card('api')}
          {card('vendor')}
        </div>
      </div>

      {summary.done && (
        <div className="migrated">
          <h3>You didn’t replace one algorithm. You migrated a system.</h3>
          <ul>
            {TAKEAWAYS.map(([title, text]) => (
              <li key={title}>
                <b>{title}</b> {text}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
