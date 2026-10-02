import { useEffect, useMemo, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { KindMark } from '../components/Finding.tsx';
import { Player } from '../learn/Player.tsx';
import type { Cue } from '../learn/Player.tsx';
import { buildScore } from '../learn/score.ts';
import { cleanLogin, LOGIN_LIMITS, MODES, runAttack, runSession } from '../learn/session.ts';
import type { AttackOutcome, Attacker, Login, Mode, Session } from '../learn/session.ts';
import { href, navigate } from '../router.ts';
import type { Route } from '../router.ts';

const MODE_ORDER: Mode[] = ['classical', 'hybrid', 'pq'];
const COMPUTER = { classical: 'an ordinary computer', quantum: 'a quantum computer' } as const;

type Run = { session: Session; attacks: Record<'classical' | 'quantum', AttackOutcome> };

const isMode = (value: string | null): value is Mode => value !== null && value in MODES;
const isAttacker = (value: string | null): value is Attacker => value === 'none' || value === 'classical' || value === 'quantum';

/** One login with real cryptography, and what each kind of attacker can then do with a recording of it. */
async function perform(mode: Mode, login?: Login): Promise<Run> {
  const session = await runSession(mode, login);
  return { session, attacks: { classical: await runAttack(session, 'classical'), quantum: await runAttack(session, 'quantum') } };
}

/**
 * A login the visitor does themselves. They type into the form on the stage
 * and press Log in; the cryptography runs on what they typed, and the stage
 * shows where it went. An attacker records the network throughout, and the
 * visitor decides what she attacks with.
 */
export function LearnView({ route }: { route: Route }) {
  const mode: Mode = isMode(route.query.get('mode')) ? (route.query.get('mode') as Mode) : 'classical';
  // A link from a scan result can ask for a moment, and for an attacker.
  const [at, asked] = [route.query.get('at'), route.query.get('attacker')];
  const [examples, setExamples] = useState<Record<Mode, Run>>();
  const [login, setLogin] = useState<Login>({ username: '', password: '' });
  /** What the visitor logged in with, once they have. From then on a change of site logs in again with it. */
  const mine = useRef<Login>(undefined);
  const [run, setRun] = useState<Run>();
  const [attacker, setAttacker] = useState<Attacker>('none');
  const [cue, setCue] = useState<Cue>({ id: 0, at: 0, play: false });
  const go = (at: number, play: boolean) => setCue((previous) => ({ id: previous.id + 1, at, play }));

  // The example login, for each kind of site: what the table below is made of, and what a link lands on.
  useEffect(() => {
    void Promise.all(MODE_ORDER.map(async (m) => [m, await perform(m)] as const)).then((entries) => setExamples(Object.fromEntries(entries) as Record<Mode, Run>));
  }, []);

  useEffect(() => {
    if (!examples) return;
    let stale = false;
    if (mine.current) {
      void perform(mode, mine.current).then((next) => {
        if (stale) return;
        setRun(next);
        setAttacker('none');
        go(0, true);
      });
    } else {
      const example = examples[mode];
      const who: Attacker = isAttacker(asked) ? asked : at === 'harvest' || at === 'forgery' ? 'quantum' : 'none';
      const moment = buildScore(example.session, who === 'none' ? undefined : example.attacks[who], true).landmarks.find((l) => l.id === at)?.t;
      setRun(example);
      setAttacker(who);
      go(moment ?? 0, moment !== undefined);
    }
    return () => {
      stale = true;
    };
  }, [examples, mode, at, asked]);

  const score = useMemo(() => (run ? buildScore(run.session, attacker === 'none' ? undefined : run.attacks[attacker], true) : undefined), [run, attacker]);
  const loginEnd = score ? (score.landmarks.find((l) => l.id === 'harvest')?.t ?? score.duration) : 0;
  const who = run?.session.login.username ?? '';
  const info = MODES[mode];
  const nextMode = MODE_ORDER[MODE_ORDER.indexOf(mode) + 1];

  async function logIn(site: Mode = mode) {
    mine.current = cleanLogin(login);
    if (site !== mode) return navigate('learn', { mode: site }); // the new site logs in once it is on screen
    setRun(await perform(mode, mine.current));
    setAttacker('none');
    go(0, true);
  }
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void logIn();
  };
  const attack = (computer: 'classical' | 'quantum') => {
    setAttacker(computer);
    go(loginEnd, true);
  };
  const logOut = () => {
    setAttacker('none');
    go(0, false);
  };

  const screen = {
    form: (
      <form className="demo-login" onSubmit={submit} autoComplete="off">
        <input
          type="text"
          name="demo-name"
          aria-label="Username: make one up"
          placeholder="any name"
          value={login.username}
          maxLength={LOGIN_LIMITS.username}
          onChange={(event) => setLogin({ ...login, username: event.target.value })}
          spellCheck={false}
          autoCapitalize="none"
          autoComplete="off"
        />
        <input
          type="text"
          name="demo-secret"
          aria-label="Password: make one up"
          placeholder="any password"
          value={login.password}
          maxLength={LOGIN_LIMITS.password}
          onChange={(event) => setLogin({ ...login, password: event.target.value })}
          spellCheck={false}
          autoCapitalize="none"
          autoComplete="off"
        />
        <button type="submit" className="primary">
          Log in
        </button>
      </form>
    ),
    waiting: <p className="screen-status">Logging in as {who}…</p>,
    welcome: (
      <p className="screen-in">
        <b>Welcome, {who}</b>
        <button type="button" className="link" onClick={logOut}>
          Log out
        </button>
      </p>
    ),
  };

  const ending =
    attacker === 'none' ? (
      <div className="next">
        <p>Mallory copied everything that crossed the network. What can she do with it?</p>
        <button type="button" className="primary" onClick={() => attack('quantum')}>
          Give her a quantum computer
        </button>
        <button type="button" onClick={() => attack('classical')}>
          Let her try with an ordinary computer
        </button>
      </div>
    ) : (
      <div className="next">
        <button type="button" onClick={() => attack(attacker === 'quantum' ? 'classical' : 'quantum')}>
          Try {COMPUTER[attacker === 'quantum' ? 'classical' : 'quantum']} instead
        </button>
        {nextMode ? (
          <button type="button" className="primary" onClick={() => void logIn(nextMode)}>
            Log in to a site that uses {nextMode === 'hybrid' ? 'hybrid key exchange' : 'post-quantum cryptography'}
          </button>
        ) : (
          <a className="button primary" href={href('')}>
            Scan a real sign-in page
          </a>
        )}
      </div>
    );

  return (
    <section className="sheet learn">
      <h1>What actually happens when you log in</h1>
      <p className="sub">Type a made-up login below and press Log in. Every step that follows is real cryptography, run in your browser on what you typed.</p>

      <div className="learn-setup">
        <span id="site-uses">This site uses</span>
        <div className="seg" role="group" aria-labelledby="site-uses">
          {MODE_ORDER.map((m) => (
            <button key={m} type="button" aria-pressed={m === mode} onClick={() => navigate('learn', { mode: m })}>
              {MODES[m].label}
            </button>
          ))}
        </div>
        <p className="fine">{info.where}</p>
      </div>

      {score ? (
        <Player
          score={score}
          cue={cue}
          screen={screen}
          invitation="Type any name and a made-up password, then press Log in."
          onStart={() => void logIn()}
          ending={ending}
        />
      ) : (
        <p className="fine">Running the cryptography…</p>
      )}

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
          <i className="swatch hostile" /> red ring: Mallory has it
        </li>
      </ul>

      {examples && (
        <div className="matrix-wrap">
          <h2>What an attacker gets, by kind of site</h2>
          <p className="sub">Every cell was computed on this page: a real decryption attempt and a real signature check. Only the quantum computer itself is simulated.</p>
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
                      {MODES[m].label}
                      <span>
                        {MODES[m].group}, {MODES[m].signatureName} signatures
                      </span>
                    </th>
                    {(['classical', 'quantum'] as const).map((computer) => {
                      const outcome = examples[m].attacks[computer];
                      const read = outcome.decryptedLogin !== undefined;
                      return (
                        <td key={computer}>
                          <span className={read ? 'bad' : 'good'}>{read ? 'Reads the recorded login, even years later' : 'Cannot read the recorded login'}</span>
                          <span className={outcome.forgeryAccepted ? 'bad' : 'good'}>{outcome.forgeryAccepted ? 'Forges a login, from the day the computer exists' : 'Cannot forge a login'}</span>
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
              In no row is the encryption itself broken. AES-256 and SHA-384 are only weakened by a quantum computer, and remain far out of reach. What falls is the public-key step
              around them.
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
