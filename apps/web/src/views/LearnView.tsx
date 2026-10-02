import { useEffect, useMemo, useState } from 'react';
import { KindMark } from '../components/Finding.tsx';
import { Player } from '../learn/Player.tsx';
import { buildScore } from '../learn/score.ts';
import { MODES, runAttack, runSession } from '../learn/session.ts';
import type { AttackOutcome, Attacker, Mode, Session } from '../learn/session.ts';
import { href, navigate } from '../router.ts';
import type { Route } from '../router.ts';

const MODE_ORDER: Mode[] = ['classical', 'hybrid', 'pq'];
const ATTACKERS: { id: Attacker; label: string }[] = [
  { id: 'none', label: 'No attacker' },
  { id: 'classical', label: 'Attacker with an ordinary computer' },
  { id: 'quantum', label: 'Attacker with a quantum computer' },
];

type Run = { session: Session; attacks: Record<'classical' | 'quantum', AttackOutcome> };

const isMode = (value: string | null): value is Mode => value !== null && value in MODES;
const isAttacker = (value: string | null): value is Attacker => ATTACKERS.some((a) => a.id === value);

/**
 * One login, on one stage, driven by one clock. The cryptography is run once
 * for each configuration when the page opens; the stage then shows those
 * values. Choosing an attacker puts her on the same stage and extends the
 * same timeline.
 */
export function LearnView({ route }: { route: Route }) {
  const [runs, setRuns] = useState<Record<Mode, Run>>();
  const at = route.query.get('at');
  const mode: Mode = isMode(route.query.get('mode')) ? (route.query.get('mode') as Mode) : 'classical';
  // A link to a moment in the attack implies an attacker.
  const attacker: Attacker = isAttacker(route.query.get('attacker')) ? (route.query.get('attacker') as Attacker) : at === 'harvest' || at === 'forgery' ? 'quantum' : 'none';

  useEffect(() => {
    void Promise.all(
      MODE_ORDER.map(async (m) => {
        const session = await runSession(m);
        return [m, { session, attacks: { classical: await runAttack(session, 'classical'), quantum: await runAttack(session, 'quantum') } }] as const;
      }),
    ).then((entries) => setRuns(Object.fromEntries(entries) as Record<Mode, Run>));
  }, []);

  const score = useMemo(() => (runs ? buildScore(runs[mode].session, attacker === 'none' ? undefined : runs[mode].attacks[attacker]) : undefined), [runs, mode, attacker]);
  const startAt = score?.landmarks.find((l) => l.id === at)?.t ?? 0;
  const choose = (next: { mode?: Mode; attacker?: Attacker }) => navigate('learn', { mode: next.mode ?? mode, attacker: next.attacker ?? attacker });
  const info = MODES[mode];

  return (
    <section className="sheet learn">
      <h1>What actually happens when you log in</h1>
      <p className="sub">One login, start to finish. Play it, or drag the timeline to any moment and look at it.</p>

      <div className="learn-setup">
        <div>
          <div className="seg" role="group" aria-label="Cryptography in use">
            {MODE_ORDER.map((m) => (
              <button key={m} type="button" aria-pressed={m === mode} onClick={() => choose({ mode: m })}>
                {MODES[m].label}
              </button>
            ))}
          </div>
          <p className="fine">{info.where}</p>
        </div>
        <div>
          <div className="seg" role="group" aria-label="Attacker">
            {ATTACKERS.map((a) => (
              <button key={a.id} type="button" aria-pressed={a.id === attacker} onClick={() => choose({ attacker: a.id })}>
                {a.label}
              </button>
            ))}
          </div>
          {attacker === 'quantum' && <p className="fine">A large, fault-tolerant quantum computer. None exists today.</p>}
        </div>
      </div>

      <ul className="grammar" aria-label="How to read the stage">
        <li>
          <i className="swatch solid" /> solid: private, never sent
        </li>
        <li>
          <i className="swatch outline" /> outline: public
        </li>
        <li>
          <i className="swatch lattice" /> dotted: post-quantum
        </li>
        <li>
          <i className="swatch secret" /> yellow: a shared secret
        </li>
        <li>
          <i className="swatch cert" /> certificate key
        </li>
        <li>
          <i className="swatch token" /> token key
        </li>
        {attacker !== 'none' && (
          <li>
            <i className="swatch hostile" /> red ring: Mallory has it
          </li>
        )}
      </ul>

      {score ? <Player key={`${mode}-${attacker}-${at ?? ''}`} score={score} attacker={attacker !== 'none'} startAt={startAt} autoplay={!at} /> : <p className="fine">Running the cryptography…</p>}

      {runs && (
        <div className="matrix-wrap">
          <h2>What an attacker gets, by setup</h2>
          <p className="sub">
            Every cell was computed on this page a moment ago: a real decryption attempt and a real signature check. Only the quantum computer itself is simulated.
          </p>
          <div className="scroll-x">
            <table className="matrix">
              <thead>
                <tr>
                  <td />
                  <th scope="col">Ordinary computer</th>
                  <th scope="col">Quantum computer</th>
                </tr>
              </thead>
              <tbody>
                {MODE_ORDER.map((m) => (
                  <tr key={m} className={m === mode ? 'current' : ''}>
                    <th scope="row">
                      <a href={href('learn', { mode: m, attacker: 'quantum', at: 'harvest' })}>{MODES[m].label}</a>
                      <span>
                        {MODES[m].group}, {MODES[m].signatureName} signatures
                      </span>
                    </th>
                    {(['classical', 'quantum'] as const).map((computer) => {
                      const outcome = runs[m].attacks[computer];
                      const read = outcome.decryptedLogin !== undefined;
                      return (
                        <td key={computer}>
                          <span className={read ? 'bad' : 'good'}>{read ? 'Reads the recorded login, even years later' : 'Cannot read the recorded login'}</span>
                          <span className={outcome.forgeryAccepted ? 'bad' : 'good'}>
                            {outcome.forgeryAccepted ? 'Forges a login, from the day the computer exists' : 'Cannot forge a login'}
                          </span>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="matrix-note">
            <KindMark kind="simulation" />
            <span>
              In no row is the encryption itself broken. AES-256 and SHA-384 are only weakened by a quantum computer, and remain far out of reach. What falls is the
              public-key step around them.
            </span>
          </p>
          <p>
            <a className="learn-link" href={href('')}>
              Scan a real sign-in page to see which row it is in
            </a>
          </p>
        </div>
      )}
    </section>
  );
}
