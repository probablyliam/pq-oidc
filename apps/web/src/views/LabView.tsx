import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Tag } from '../components/Tag.tsx';
import { Cracker } from '../lab/Cracker.tsx';
import { AttackScene, ProcessScene } from '../lab/Diagram.tsx';
import type { Job, Phase } from '../lab/Diagram.tsx';
import { cleanLogin, DEFAULT_SETUP, hex, KEX, LOGIN_LIMITS, passwordIn, runAttack, runSession, SIG } from '../lab/session.ts';
import type { Attack, Computer, Kex, Login, Session, Setup, Sig } from '../lab/session.ts';
import { href, navigate } from '../router.ts';
import type { Route } from '../router.ts';

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

const prefersReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function Value({ label, bytes, note, pq }: { label: string; bytes: string; note?: string; pq?: boolean }) {
  return (
    <div className={`val ${pq ? 'pq' : ''}`}>
      <span className="val-label">{label}</span>
      <code className="val-bytes">{bytes}</code>
      {note && <span className="val-note">{note}</span>}
    </div>
  );
}

/** One of the three processes. Shown ghosted before login, revealed with its diagram after. */
function Process({ n, title, sub, pq, live, scene, children }: { n: number; title: string; sub: React.ReactNode; pq: boolean; live: boolean; scene: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className={`process ${pq ? 'pq' : ''} ${live ? 'live' : 'ghost'}`} style={{ ['--i' as string]: n - 1 }}>
      <header>
        <span className="process-n">{n}</span>
        <div>
          <h3>{title}</h3>
          <p className="process-sub">{sub}</p>
        </div>
      </header>
      {scene}
      {live && <div className="process-body">{children}</div>}
    </section>
  );
}

const JOBS: { job: Job; title: string }[] = [
  { job: 'recording', title: 'Read your password from the recording' },
  { job: 'site', title: 'Pretend to be the site' },
  { job: 'token', title: 'Forge a sign-in token' },
];

/** One attacker job. The same attempt runs for either computer; it settles on won or lost. */
function AttackRow({ n, job, title, computer, attackKey, won, target, pq, wonText, lostText }: {
  n: number;
  job: Job;
  title: string;
  computer: Computer;
  /** Changes whenever the session or the computer does, so the attempt replays. */
  attackKey: string;
  won: boolean;
  target: string;
  pq: boolean;
  wonText: string;
  lostText: string;
}) {
  const [phase, setPhase] = useState<Phase>('idle');
  useEffect(() => {
    if (prefersReducedMotion()) {
      setPhase(won ? 'won' : 'lost');
      return;
    }
    setPhase('working');
    // The work takes a beat; a quantum success runs a touch longer so the "solve" lands last.
    const t = setTimeout(() => setPhase(won ? 'won' : 'lost'), won ? 1500 : 1100);
    return () => clearTimeout(t);
  }, [attackKey, won]);

  return (
    <section className={`attack-row phase-${phase}`}>
      <header>
        <span className="process-n">{n}</span>
        <h4>{title}</h4>
        {(phase === 'won' || phase === 'lost') && <span className={`outcome ${phase}`}>{phase === 'won' ? 'Taken over' : 'Blocked'}</span>}
      </header>
      <AttackScene job={job} phase={phase} pq={pq} />
      <Cracker target={target} active={phase === 'working' || phase === 'won'} solved={phase === 'won'} />
      <p className="attack-text">{phase === 'working' ? (computer === 'quantum' ? 'Running the math…' : 'Trying every key…') : phase === 'won' ? wonText : phase === 'lost' ? lostText : ''}</p>
    </section>
  );
}

/**
 * The login lab. The visitor sets what the site uses, logs in with a made-up
 * password, and the three processes reveal with real values. A second panel is
 * the attacker: switch her computer and each job runs the same attempt, which
 * fails for an ordinary computer and, for the parts that are still classical,
 * succeeds for a quantum one and shows what she does next. Nothing plays on its
 * own; every change follows a toggle.
 */
export function LabView({ route }: { route: Route }) {
  const setup = setupFromRoute(route);
  const setupKey = `${setup.kex}-${setup.cert}-${setup.token}`;
  const [login, setLogin] = useState<Login>({ username: '', password: '' });
  const [session, setSession] = useState<Session>();
  const [attack, setAttack] = useState<Attack>();
  const [computer, setComputer] = useState<Computer>('ordinary');
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
  const live = Boolean(session);
  const stolen = attack?.key.decryptedLogin ? passwordIn(attack.key.decryptedLogin) : '';
  const attackKey = `${setupKey}-${computer}-${session ? 'in' : 'out'}`;
  const wonFor: Record<Job, boolean> = {
    recording: attack?.key.decryptedLogin !== undefined,
    site: attack?.site.accepted ?? false,
    token: attack?.token.accepted ?? false,
  };
  const targetFor: Record<Job, string> = {
    recording: session ? hex(session.held.client.secretKey, 12) : '',
    site: session ? hex(session.held.certPrivate, 12) : '',
    token: session ? hex(session.held.tokenPrivate, 12) : '',
  };
  const lostFor = (job: Job, pq: boolean): string =>
    computer === 'quantum' && pq
      ? { recording: 'The ML-KEM half has no known quantum attack, so the recording stays sealed.', site: 'ML-DSA has no known quantum attack. A browser rejects her.', token: 'ML-DSA has no known quantum attack. Her forgery is rejected.' }[job]
      : { recording: 'An ordinary computer cannot work out the private half. The recording stays sealed.', site: 'An ordinary computer cannot recover the certificate key. A browser rejects her.', token: 'An ordinary computer cannot recover the signing key. Her forgery is rejected.' }[job];
  const wonFor2 = (job: Job): string =>
    ({
      recording: `She re-derived the key and opened the recording. Your password: ${stolen}.`,
      site: 'She recovered the certificate’s private key, so she can sign as the site. A browser accepts her.',
      token: `She recovered the signing key and wrote a token that says she is ${who}. The site accepts it.`,
    })[job];
  const jobPq: Record<Job, boolean> = { recording: KEX[setup.kex].pq, site: SIG[setup.cert].pq, token: SIG[setup.token].pq };

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

      <ol className="processes" aria-label="What happens when you log in">
        <li>
          <Process n={1} title="Key exchange" live={live} pq={KEX[setup.kex].pq} scene={<ProcessScene step="kex" pq={KEX[setup.kex].pq} live={live} />} sub={<>{KEX[setup.kex].name} <Tag kind={KEX[setup.kex].pq ? 'PQC' : 'classical'} /></>}>
            {session && (
              <>
                <Value label="Shared secret" bytes={hex(session.sharedSecret, 7)} note="never sent" pq={KEX[setup.kex].pq} />
                <Value label="Your login, encrypted" bytes={hex(session.loginRecord.subarray(5), 8)} note="on the wire" />
              </>
            )}
          </Process>
        </li>
        <li>
          <Process n={2} title="Site proves who it is" live={live} pq={SIG[setup.cert].pq} scene={<ProcessScene step="cert" pq={SIG[setup.cert].pq} live={live} />} sub={<>{SIG[setup.cert].name} <Tag kind={SIG[setup.cert].pq ? 'PQC' : 'classical'} /></>}>
            {session && (
              <>
                <Value label="Signature over the handshake" bytes={hex(session.certificateVerify, 8)} note={`${session.certificateVerify.length.toLocaleString('en-US')} bytes`} pq={SIG[setup.cert].pq} />
                <p className={`check ${session.certificateVerifyValid ? 'ok' : 'bad'}`}>{session.certificateVerifyValid ? 'This is the real payroll.example' : 'Did not verify'}</p>
              </>
            )}
          </Process>
        </li>
        <li>
          <Process n={3} title="Sign-in token" live={live} pq={SIG[setup.token].pq} scene={<ProcessScene step="token" pq={SIG[setup.token].pq} live={live} />} sub={<>{SIG[setup.token].name} <Tag kind={SIG[setup.token].pq ? 'PQC' : 'classical'} /></>}>
            {session && (
              <>
                <Value label={`Token for ${who}`} bytes={hex(new TextEncoder().encode(session.token), 8)} note={`${session.token.length.toLocaleString('en-US')} bytes`} pq={SIG[setup.token].pq} />
                <p className={`check ${session.tokenValid ? 'ok' : 'bad'}`}>{session.tokenValid ? 'Only the site can make one' : 'Did not verify'}</p>
              </>
            )}
          </Process>
        </li>
      </ol>

      {session && attack && (
        <div className="attacker">
          <header className="attacker-head">
            <div>
              <h2>Be the attacker</h2>
              <p className="sub">She copied everything that crossed the network. Pick her computer and watch each attempt.</p>
            </div>
            <div className="seg big" role="group" aria-label="The attacker’s computer">
              <button type="button" aria-pressed={computer === 'ordinary'} onClick={() => setComputer('ordinary')}>
                Ordinary computer
              </button>
              <button type="button" aria-pressed={computer === 'quantum'} onClick={() => setComputer('quantum')}>
                Quantum computer
              </button>
            </div>
          </header>

          <ol className="attack-rows">
            {JOBS.map(({ job, title }, i) => (
              <li key={job}>
                <AttackRow n={i + 1} job={job} title={title} computer={computer} attackKey={attackKey} won={wonFor[job]} target={targetFor[job]} pq={jobPq[job]} wonText={wonFor2(job)} lostText={lostFor(job, jobPq[job])} />
              </li>
            ))}
          </ol>
          <p className="attacker-foot">
            The cipher itself is never the target: a quantum computer only weakens AES-256 slightly. What falls is the public-key step around it. <a href={href('')}>Scan a real sign-in page</a> to see which of these a site is exposed to.
          </p>
        </div>
      )}
    </section>
  );
}
