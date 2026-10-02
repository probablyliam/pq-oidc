import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Tag } from '../components/Tag.tsx';
import { Cracker } from '../lab/Cracker.tsx';
import { cleanLogin, DEFAULT_SETUP, hex, KEX, LOGIN_LIMITS, passwordIn, runAttack, runSession, SIG } from '../lab/session.ts';
import type { Attack, Computer, Kex, Login, Session, Setup, Sig } from '../lab/session.ts';
import { href, navigate } from '../router.ts';
import type { Route } from '../router.ts';

/** The three public-key choices a site makes, each switchable on its own. */
const CHOICES = [
  { key: 'kex' as const, label: 'Key exchange', options: [['x25519', KEX.x25519], ['hybrid', KEX.hybrid]] as const },
  { key: 'cert' as const, label: 'Site’s certificate', options: [['ecdsa', SIG.ecdsa], ['mldsa', SIG.mldsa]] as const },
  { key: 'token' as const, label: 'Sign-in token', options: [['ecdsa', SIG.ecdsa], ['mldsa', SIG.mldsa]] as const },
];

const isKex = (v: string | null): v is Kex => v === 'x25519' || v === 'hybrid';
const isSig = (v: string | null): v is Sig => v === 'ecdsa' || v === 'mldsa';
const setupFromRoute = (route: Route): Setup => ({
  kex: isKex(route.query.get('kex')) ? (route.query.get('kex') as Kex) : DEFAULT_SETUP.kex,
  cert: isSig(route.query.get('cert')) ? (route.query.get('cert') as Sig) : DEFAULT_SETUP.cert,
  token: isSig(route.query.get('token')) ? (route.query.get('token') as Sig) : DEFAULT_SETUP.token,
});

/** A labelled value, with its bytes shown as hex. The grammar: dotted border = post-quantum, solid = classical. */
function Value({ label, bytes, note, pq }: { label: string; bytes: string; note?: string; pq?: boolean }) {
  return (
    <div className={`val ${pq ? 'pq' : ''}`}>
      <span className="val-label">{label}</span>
      <code className="val-bytes">{bytes}</code>
      {note && <span className="val-note">{note}</span>}
    </div>
  );
}

/** One of the three processes behind the login, filled once the visitor has logged in. */
function Process({ n, title, pq, children }: { n: number; title: string; pq: boolean; children: React.ReactNode }) {
  return (
    <section className={`process ${pq ? 'pq' : ''}`}>
      <header>
        <span className="process-n">{n}</span>
        <h3>{title}</h3>
      </header>
      {children}
    </section>
  );
}

/** One thing the attacker tries, with the "working it out" readout and the outcome. */
function AttackRow({ n, title, done, computer, target, solved, won, wonText, lostText }: {
  n: number;
  title: string;
  done: boolean;
  computer: Computer;
  target: string;
  solved: boolean;
  won: boolean;
  wonText: string;
  lostText: string;
}) {
  return (
    <section className={`attack-row ${done ? (won ? 'won' : 'lost') : ''}`}>
      <header>
        <span className="process-n">{n}</span>
        <h4>{title}</h4>
        {done && <span className={`outcome ${won ? 'won' : 'lost'}`}>{won ? 'Taken over' : 'Blocked'}</span>}
      </header>
      {done && (
        <>
          <Cracker target={target} active={computer === 'quantum'} solved={solved} />
          <p className="attack-text">{won ? wonText : lostText}</p>
        </>
      )}
    </section>
  );
}

/**
 * The login lab. The visitor sets what the site uses, logs in with a made-up
 * password, and sees the three processes that run, with real values. A second
 * panel is the attacker: switch the computer she has and watch which processes
 * she can take over. Nothing plays on its own; everything follows the toggles.
 */
export function LabView({ route }: { route: Route }) {
  const setup = setupFromRoute(route);
  const setupKey = `${setup.kex}-${setup.cert}-${setup.token}`;
  const [login, setLogin] = useState<Login>({ username: '', password: '' });
  const [session, setSession] = useState<Session>();
  const [attack, setAttack] = useState<Attack>();
  const [computer, setComputer] = useState<Computer>('ordinary');
  // The login the visitor committed to by pressing Log in; a toggle re-runs with it.
  const committed = useRef<Login>(undefined);
  const last = useRef<Session>(undefined);

  const change = (key: keyof Setup, value: string) => navigate('lab', { ...setup, [key]: value, computer: computer === 'quantum' ? 'quantum' : undefined });

  async function logIn(next = cleanLogin(login)) {
    committed.current = next;
    const s = await runSession(setup, next, last.current);
    last.current = s;
    setSession(s);
  }
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void logIn();
  };
  const logOut = () => {
    committed.current = undefined;
    last.current = undefined;
    setSession(undefined);
    setAttack(undefined);
    setComputer('ordinary');
  };

  // A change to any choice re-runs the login the visitor already did, keeping the keys of the parts that did not change.
  useEffect(() => {
    if (committed.current) void logIn(committed.current);
  }, [setupKey]);

  // The attacker's result follows the session and the computer she has.
  useEffect(() => {
    if (!session) return setAttack(undefined);
    let fresh = true;
    void runAttack(session, computer).then((a) => fresh && setAttack(a));
    return () => {
      fresh = false;
    };
  }, [session, computer]);

  useEffect(() => {
    if (route.query.get('computer') === 'quantum') setComputer('quantum');
  }, [route.query]);

  const who = session?.login.username ?? '';
  const stolen = attack?.key.decryptedLogin ? passwordIn(attack.key.decryptedLogin) : '';

  return (
    <section className="sheet lab">
      <header className="lab-head">
        <h1>The login lab</h1>
        <p className="sub">Set what the site uses, log in with a password you make up, and watch the three things that protect it. Then switch to the attacker and see what a quantum computer changes.</p>
      </header>

      <div className="controls" role="group" aria-label="What this site uses">
        {CHOICES.map((choice) => (
          <div key={choice.key} className="control">
            <span className="control-label">{choice.label}</span>
            <div className="seg">
              {choice.options.map(([value, meta]) => (
                <button key={value} type="button" aria-pressed={setup[choice.key] === value} onClick={() => change(choice.key, value)}>
                  {meta.name} <Tag kind={meta.pq ? 'PQC' : 'classical'} />
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>

      <div className="screen-card">
        <p className="screen-site">payroll.example</p>
        {session ? (
          <p className="screen-in">
            <b>Signed in as {who}</b>
            <button type="button" className="link" onClick={logOut}>
              Log out
            </button>
          </p>
        ) : (
          <form className="demo-login" onSubmit={submit} autoComplete="off">
            <input type="text" aria-label="Username: make one up" placeholder="any name" value={login.username} maxLength={LOGIN_LIMITS.username} onChange={(e) => setLogin({ ...login, username: e.target.value })} spellCheck={false} autoCapitalize="none" autoComplete="off" />
            <input type="text" aria-label="Password: make one up" placeholder="any password" value={login.password} maxLength={LOGIN_LIMITS.password} onChange={(e) => setLogin({ ...login, password: e.target.value })} spellCheck={false} autoCapitalize="none" autoComplete="off" />
            <button type="submit" className="primary">
              Log in
            </button>
          </form>
        )}
      </div>

      {session && (
        <>
          <div className="processes">
            <Process n={1} title="Key exchange" pq={KEX[setup.kex].pq}>
              <p className="process-sub">
                {KEX[setup.kex].name} <Tag kind={KEX[setup.kex].pq ? 'PQC' : 'classical'} />
              </p>
              <Value label="Browser sends" bytes={hex(session.clientShare, 7)} note="public" />
              <Value label="Server sends" bytes={hex(session.serverShare, 7)} note="public" />
              <Value label="Shared secret" bytes={hex(session.sharedSecret, 7)} note="never sent" pq={KEX[setup.kex].pq} />
              <p className="process-note">Your password rides inside a channel keyed from this secret.</p>
              <Value label="Encrypted login" bytes={hex(session.loginRecord.subarray(5), 9)} note="on the wire" />
            </Process>

            <Process n={2} title="Site proves who it is" pq={SIG[setup.cert].pq}>
              <p className="process-sub">
                {SIG[setup.cert].name} <Tag kind={SIG[setup.cert].pq ? 'PQC' : 'classical'} />
              </p>
              <Value label="Signature over the handshake" bytes={hex(session.certificateVerify, 9)} note={`${session.certificateVerify.length.toLocaleString('en-US')} bytes`} pq={SIG[setup.cert].pq} />
              <p className={`check ${session.certificateVerifyValid ? 'ok' : 'bad'}`}>{session.certificateVerifyValid ? 'Browser checked it: this is the real payroll.example' : 'Did not verify'}</p>
            </Process>

            <Process n={3} title="Sign-in token" pq={SIG[setup.token].pq}>
              <p className="process-sub">
                {SIG[setup.token].name} <Tag kind={SIG[setup.token].pq ? 'PQC' : 'classical'} />
              </p>
              <Value label={`Token for ${who}`} bytes={hex(new TextEncoder().encode(session.token), 9)} note={`${session.token.length.toLocaleString('en-US')} bytes`} pq={SIG[setup.token].pq} />
              <p className={`check ${session.tokenValid ? 'ok' : 'bad'}`}>{session.tokenValid ? 'Signed by the site; only it can make one' : 'Did not verify'}</p>
            </Process>
          </div>

          <div className="attacker">
            <header className="attacker-head">
              <div>
                <h2>Be the attacker</h2>
                <p className="sub">She copied everything that crossed the network. What she can do with it depends on her computer.</p>
              </div>
              <div className="seg" role="group" aria-label="The attacker’s computer">
                <button type="button" aria-pressed={computer === 'ordinary'} onClick={() => setComputer('ordinary')}>
                  Ordinary computer
                </button>
                <button type="button" aria-pressed={computer === 'quantum'} onClick={() => setComputer('quantum')}>
                  Quantum computer
                </button>
              </div>
            </header>

            {attack && (
              <div className="attack-rows">
                <AttackRow
                  n={1}
                  title="Read your password from the recording"
                  done
                  computer={computer}
                  target={hex(session.held.client.secretKey, 10)}
                  solved={attack.key.ecdhRecovered && attack.key.decryptedLogin !== undefined}
                  won={attack.key.decryptedLogin !== undefined}
                  wonText={`She worked out the browser’s private half, re-derived the key, and opened the recording. Your password: ${stolen}.`}
                  lostText={computer === 'quantum' && KEX[setup.kex].pq ? 'She recovered the classical half, but the ML-KEM half has no known quantum attack. The recording stays sealed.' : 'An ordinary computer cannot work out the private half. The recording stays sealed.'}
                />
                <AttackRow
                  n={2}
                  title="Pretend to be the site"
                  done
                  computer={computer}
                  target={hex(session.held.certPrivate, 10)}
                  solved={attack.site.keyRecovered}
                  won={attack.site.accepted}
                  wonText="She recovered the certificate’s private key, so she can sign as the site. A browser would accept her."
                  lostText={computer === 'quantum' && SIG[setup.cert].pq ? 'The certificate uses ML-DSA. No quantum attack recovers its key. A browser rejects her.' : 'An ordinary computer cannot recover the certificate key. A browser rejects her.'}
                />
                <AttackRow
                  n={3}
                  title="Forge a sign-in token"
                  done
                  computer={computer}
                  target={hex(session.held.tokenPrivate, 10)}
                  solved={attack.token.keyRecovered}
                  won={attack.token.accepted}
                  wonText={`She recovered the signing key and wrote a token that says she is ${who}. The site accepts it, and never saw a password.`}
                  lostText={computer === 'quantum' && SIG[setup.token].pq ? 'The token is signed with ML-DSA. No quantum attack recovers the key. Her forgery is rejected.' : 'An ordinary computer cannot recover the signing key. Her forgery is rejected.'}
                />
              </div>
            )}
            <p className="attacker-foot">
              The cipher itself is never the target: a quantum computer only weakens AES-256 slightly. What falls is the public-key step around it. <a href={href('')}>Scan a real sign-in page</a> to see which of these a site is exposed to.
            </p>
          </div>
        </>
      )}
    </section>
  );
}
