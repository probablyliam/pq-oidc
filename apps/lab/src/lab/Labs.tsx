import { useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import { MODES, runAttack, runLogin } from './crypto.ts';
import type { AttackResult, Computer, Mode, Session } from './crypto.ts';
import { attackEvents, loginEvents } from './events.ts';
import type { Thing } from './events.ts';
import { PlayerControls, ProtocolFlow } from './ProtocolFlow.tsx';
import { useSequence } from './useSequence.ts';

const MODE_ORDER: Mode[] = ['classical', 'hybrid', 'pq'];
const PRIVATE_KEY: Thing = { kind: 'private-key', label: 'Server’s private key', value: 'never leaves the server' };
const PUBLIC_KEY: Thing = { kind: 'public-key', label: 'Server’s public key' };

function ModePicker({ mode, onPick }: { mode: Mode; onPick: (mode: Mode) => void }) {
  const info = MODES[mode];
  return (
    <div className="mode-picker">
      <div className="seg" role="group" aria-label="Cryptography in use">
        {MODE_ORDER.map((m) => (
          <button key={m} type="button" aria-pressed={m === mode} onClick={() => onPick(m)}>
            {MODES[m].label}
          </button>
        ))}
      </div>
      <dl className="mode-facts">
        <div className={info.keyAgreement.quantumSafe ? 'safe' : 'weak'}>
          <dt>Connection secret</dt>
          <dd>
            {info.keyAgreement.name}
            <span>{info.keyAgreement.quantumSafe ? 'quantum-safe' : 'quantum-breakable'}</span>
          </dd>
        </div>
        <div className={info.signature.quantumSafe ? 'safe' : 'weak'}>
          <dt>Signatures</dt>
          <dd>
            {info.signature.name}
            <span>{info.signature.quantumSafe ? 'quantum-safe' : 'quantum-breakable'}</span>
          </dd>
        </div>
      </dl>
    </div>
  );
}

/**
 * The Login Lab and the attack on it. They share one mode and one recorded
 * login, so the attack is always against the login you just watched.
 */
export function Labs({ mode, onMode }: { mode: Mode; onMode: (mode: Mode) => void }) {
  const [session, setSession] = useState<Session>();
  const [busy, setBusy] = useState(false);
  const login = useMemo(() => (session ? loginEvents(session) : []), [session]);
  const loginPlayer = useSequence(login.length, 1150);

  const [computer, setComputer] = useState<Computer>('quantum');
  const [attack, setAttack] = useState<{ session: Session; result: AttackResult }>();
  const attackSteps = useMemo(() => (attack ? attackEvents(attack.session, attack.result) : []), [attack]);
  const attackPlayer = useSequence(attackSteps.length, 1700);
  const [found, setFound] = useState<Record<string, AttackResult>>({});

  // A different mode is a different login: start both scenes over.
  const [shownMode, setShownMode] = useState(mode);
  if (shownMode !== mode) {
    setShownMode(mode);
    setSession(undefined);
    setAttack(undefined);
    loginPlayer.reset();
    attackPlayer.reset();
  }

  async function onLogin(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setSession(await runLogin(mode));
    setBusy(false);
    loginPlayer.start();
  }

  async function onAttack() {
    setBusy(true);
    const recorded = session ?? (await runLogin(mode));
    const result = await runAttack(recorded, computer);
    setSession(recorded);
    setAttack({ session: recorded, result });
    setBusy(false);
    attackPlayer.start();
  }

  // An attack counts as "tried" once its last step has been shown.
  useEffect(() => {
    if (attack && attackPlayer.finished) {
      setFound((f) => ({ ...f, [`${attack.session.mode}-${attack.result.computer}`]: attack.result }));
    }
  }, [attack, attackPlayer.finished]);

  const loggedIn = loginPlayer.finished;
  const loggingIn = loginPlayer.index > 0 && !loggedIn;
  const info = MODES[mode];
  const lastAttack = attack && attackPlayer.finished ? attack.result : undefined;
  const somethingBroke = lastAttack && (lastAttack.readLogin !== undefined || lastAttack.forgeryAccepted);

  return (
    <>
      <section className="block" id="lab">
        <h2>What actually happens when you log in?</h2>
        <p className="sub">Press Log in and watch what your browser and the server do before you see the next page.</p>
        <ModePicker mode={mode} onPick={onMode} />

        <ProtocolFlow
          events={login}
          index={loginPlayer.index}
          initial={{ server: [PRIVATE_KEY] }}
          idleHint="Nothing has been sent yet."
          browserScreen={
            loggedIn ? (
              <div className="app-home">
                <b className="success">Login successful</b>
                <button
                  type="button"
                  onClick={() => {
                    setSession(undefined);
                    loginPlayer.reset();
                  }}
                >
                  Log out
                </button>
              </div>
            ) : loggingIn ? (
              <div className="app-home">
                <b>Payroll</b>
                <span>Logging in as alice@example.com…</span>
              </div>
            ) : (
              <form className="login-form" onSubmit={onLogin}>
                <b>Payroll</b>
                <label>
                  Username
                  <input defaultValue="alice@example.com" autoComplete="off" />
                </label>
                <label>
                  Password
                  <input type="password" defaultValue="correct-horse" autoComplete="off" />
                </label>
                <button type="submit" className="primary" disabled={busy}>
                  Log in
                </button>
              </form>
            )
          }
          controls={<PlayerControls events={login} player={loginPlayer} />}
        />
      </section>

      <section className="block" id="attack">
        <h2>Now try to break it</h2>
        <p className="sub">
          Mallory recorded that login from the network. Choose her computer and see how far she gets against{' '}
          <b>{info.label.toLowerCase()}</b> cryptography.
        </p>

        <div className="setup">
          <div className="seg" role="group" aria-label="Attacker's computer">
            <button type="button" aria-pressed={computer === 'classical'} onClick={() => setComputer('classical')}>
              Classical computer
            </button>
            <button type="button" aria-pressed={computer === 'quantum'} onClick={() => setComputer('quantum')}>
              Quantum computer
            </button>
          </div>
          <button type="button" className="danger" disabled={busy} onClick={() => void onAttack()}>
            {attack ? 'Run the attack again' : 'Run the attack'}
          </button>
          {computer === 'quantum' && <span className="fine">A large, fault-tolerant quantum computer. None exists yet.</span>}
        </div>

        <ProtocolFlow
          attacker
          events={attackSteps}
          index={attackPlayer.index}
          initial={{
            browser: [{ kind: 'token', label: 'Login token' }],
            server: [PRIVATE_KEY, PUBLIC_KEY],
          }}
          idleHint="Choose a computer and run the attack."
          browserScreen={<b className="success">Alice is logged in</b>}
          controls={<PlayerControls events={attackSteps} player={attackPlayer} />}
        />

        <table className="results">
          <caption>What Mallory managed, by setup</caption>
          <thead>
            <tr>
              <td />
              <th scope="col">Classical computer</th>
              <th scope="col">Quantum computer</th>
            </tr>
          </thead>
          <tbody>
            {MODE_ORDER.map((m) => (
              <tr key={m} className={m === mode ? 'current' : ''}>
                <th scope="row">
                  <button type="button" className="link" onClick={() => onMode(m)}>
                    {MODES[m].label}
                  </button>
                </th>
                {(['classical', 'quantum'] as const).map((c) => {
                  const r = found[`${m}-${c}`];
                  return (
                    <td key={c}>
                      {r ? (
                        <>
                          <span className={r.readLogin !== undefined ? 'bad' : 'good'}>
                            {r.readLogin !== undefined ? 'Read the recorded login' : 'Couldn’t read the login'}
                          </span>
                          <span className={r.forgeryAccepted ? 'bad' : 'good'}>
                            {r.forgeryAccepted ? 'Forged a login' : 'Couldn’t forge a login'}
                          </span>
                        </>
                      ) : (
                        <span className="untried">Not tried</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>

        {somethingBroke && mode !== 'pq' && (
          <p className="next-question">
            {mode === 'hybrid'
              ? 'The connection held, but the login could still be forged. A quantum-safe connection is not a quantum-safe login.'
              : 'Both layers fell.'}{' '}
            <button type="button" className="link" onClick={() => onMode(mode === 'classical' ? 'hybrid' : 'pq')}>
              {mode === 'classical' ? 'Protect the connection and try again' : 'Protect the signatures too and try again'}
            </button>
          </p>
        )}
      </section>
    </>
  );
}
