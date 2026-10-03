import { useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { Tag } from '../components/Tag.tsx';
import { Cracker } from '../lab/Cracker.tsx';
import { AttackScene, ProcessScene } from '../lab/Diagram.tsx';
import type { Job, Phase } from '../lab/Diagram.tsx';
import { cleanLogin, DEFAULT_SETUP, hex, KEX, LOGIN_LIMITS, passwordIn, publicBytes, runAttack, runSession, SIG } from '../lab/session.ts';
import type { Attack, Computer, Kex, Login, Session, Setup, Sig } from '../lab/session.ts';
import { href, navigate } from '../router.ts';
import type { Route } from '../router.ts';

const CHOICES = [
  { key: 'kex' as const, label: 'Key exchange', options: [['x25519', KEX.x25519], ['hybrid', KEX.hybrid]] as const },
  { key: 'cert' as const, label: 'Site’s certificate', options: [['ecdsa', SIG.ecdsa], ['mldsa', SIG.mldsa]] as const },
  { key: 'token' as const, label: 'Sign-in token', options: [['ecdsa', SIG.ecdsa], ['mldsa', SIG.mldsa]] as const },
];

/** How the lab paces itself, in milliseconds. Everything here follows a press; nothing starts by itself. */
const PACE = {
  /** Between one login step revealing and the next. */
  step: 1100,
  /** After the last step, before the attacker's panel appears. */
  attackerIn: 500,
  /** How long an attempt works before it fails, or before it solves. */
  fail: 1100,
  solve: 1500,
  /** Between one job finishing and the next starting. */
  between: 250,
};

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

/** One of the three processes: ghosted until its turn, then revealed with its diagram and values. */
function Process({ n, title, sub, pq, live, scene, children }: { n: number; title: string; sub: ReactNode; pq: boolean; live: boolean; scene: ReactNode; children: ReactNode }) {
  return (
    <section className={`process ${pq ? 'pq' : ''} ${live ? 'live' : 'ghost'}`}>
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
  { job: 'recording', title: 'Read your recorded password' },
  { job: 'site', title: 'Pretend to be the site' },
  { job: 'token', title: 'Forge a sign-in token' },
];

/** One line of an attempt's working: a real value, and whether that step went her way. */
export interface Line {
  text: string;
  value?: string;
  ok?: boolean;
}

/**
 * One attacker job. Idle until a run is asked for; then, after its turn comes,
 * the same attempt runs whichever computer she has, and settles on won or lost.
 * Once settled, it shows its working: the chain of real values it computed.
 */
function AttackRow({ n, job, title, computer, runKey, startAt, won, target, pq, wonText, lostText, lines }: {
  n: number;
  job: Job;
  title: string;
  computer?: Computer;
  /** Identifies one run; undefined means no run has been asked for. A new value replays. */
  runKey?: string;
  /** When this job's turn comes, from the start of the run. */
  startAt: number;
  won: boolean;
  target: string;
  pq: boolean;
  wonText: string;
  lostText: string;
  lines: Line[];
}) {
  const [phase, setPhase] = useState<Phase>('idle');
  useEffect(() => {
    if (runKey === undefined) {
      setPhase('idle');
      return;
    }
    if (prefersReducedMotion()) {
      setPhase(won ? 'won' : 'lost');
      return;
    }
    setPhase('idle');
    const start = setTimeout(() => setPhase('working'), startAt);
    const end = setTimeout(() => setPhase(won ? 'won' : 'lost'), startAt + (won ? PACE.solve : PACE.fail));
    return () => {
      clearTimeout(start);
      clearTimeout(end);
    };
  }, [runKey, startAt, won]);

  const text = phase === 'working' ? (computer === 'quantum' ? 'Running the maths…' : 'Trying every key…') : phase === 'won' ? wonText : phase === 'lost' ? lostText : '';
  return (
    <section className={`attack-row phase-${phase}`}>
      <header>
        <span className="process-n">{n}</span>
        <h4>{title}</h4>
        {(phase === 'won' || phase === 'lost') && <span className={`outcome ${phase}`}>{phase === 'won' ? 'Taken over' : 'Blocked'}</span>}
      </header>
      <AttackScene job={job} phase={phase} pq={pq} />
      <Cracker target={target} active={phase === 'working' || phase === 'won'} solved={phase === 'won'} />
      <p className="attack-text">{text}</p>
      {(phase === 'won' || phase === 'lost') && (
        <ol className="derive" aria-label="Her working">
          {lines.map((line, i) => (
            <li key={i} className={line.ok === true ? 'ok' : line.ok === false ? 'bad' : ''}>
              <span>{line.text}</span>
              {line.value && <code>{line.value}</code>}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/**
 * The login lab. The visitor sets what the site uses and logs in with a
 * made-up password; the three processes then reveal one at a time with real
 * values. The attacker's panel appears last and waits: picking her computer
 * runs the three jobs in turn, each the same attempt, each ending as the
 * cryptography decides. Nothing plays until something is pressed.
 */
export function LabView({ route }: { route: Route }) {
  const setup = setupFromRoute(route);
  const setupKey = `${setup.kex}-${setup.cert}-${setup.token}`;
  const [login, setLogin] = useState<Login>({ username: '', password: '' });
  const [session, setSession] = useState<Session>();
  /** The attack, with the session it was computed for, so a stale one is never shown against a new login. */
  const [attack, setAttack] = useState<{ for: Session; result: Attack }>();
  /** How far the login has revealed: 0 nothing, 1..3 that many steps, 4 the attacker's panel too. */
  const [stage, setStage] = useState(0);
  const [computer, setComputer] = useState<Computer>();
  const committed = useRef<Login>(undefined);
  const last = useRef<Session>(undefined);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const stopTimers = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  };
  useEffect(() => stopTimers, []);

  const change = (key: keyof Setup, value: string) => navigate('lab', { ...setup, [key]: value, computer });

  /** The first login reveals the steps in turn, then the attacker's panel. A re-run after a toggle only updates them in place. */
  function reveal() {
    const asked = route.query.get('computer') === 'quantum' ? 'quantum' : undefined;
    if (prefersReducedMotion()) {
      setStage(4);
      if (asked) setComputer(asked);
      return;
    }
    stopTimers();
    for (const n of [1, 2, 3]) timers.current.push(setTimeout(() => setStage(n), (n - 1) * PACE.step));
    timers.current.push(
      setTimeout(() => {
        setStage(4);
        // A link from a scan result that asked for a quantum attacker gets it, once there is something to attack.
        if (asked) setComputer(asked);
      }, 2 * PACE.step + 600 + PACE.attackerIn),
    );
  }

  async function logIn(next = cleanLogin(login)) {
    const first = committed.current === undefined;
    committed.current = next;
    const s = await runSession(setup, next, last.current);
    last.current = s;
    setSession(s);
    if (first) reveal();
  }
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void logIn();
  };
  const logOut = () => {
    stopTimers();
    committed.current = undefined;
    last.current = undefined;
    setSession(undefined);
    setAttack(undefined);
    setComputer(undefined);
    setStage(0);
  };

  // A change to any choice re-runs the login the visitor already did, keeping the keys of the parts that did not change.
  useEffect(() => {
    if (committed.current) void logIn(committed.current);
  }, [setupKey]);

  useEffect(() => {
    if (!session || !computer) return setAttack(undefined);
    let fresh = true;
    void runAttack(session, computer).then((result) => fresh && setAttack({ for: session, result }));
    return () => {
      fresh = false;
    };
  }, [session, computer]);

  const who = session?.login.username ?? '';
  const ready = attack !== undefined && attack.for === session && attack.result.computer === computer;
  const result = ready ? attack.result : undefined;
  const stolen = result?.key.decryptedLogin ? passwordIn(result.key.decryptedLogin) : '';
  const runKey = ready && session ? `${setupKey}-${computer}-${session.token.slice(-16)}` : undefined;
  const wonFor: Record<Job, boolean> = {
    recording: result?.key.decryptedLogin !== undefined,
    site: result?.site.accepted ?? false,
    token: result?.token.accepted ?? false,
  };
  // Jobs run one after another: each starts when the previous has settled.
  const startAt: Record<Job, number> = { recording: 0, site: 0, token: 0 };
  let clock = 0;
  for (const { job } of JOBS) {
    startAt[job] = clock;
    clock += (wonFor[job] ? PACE.solve : PACE.fail) + PACE.between;
  }
  const targetFor: Record<Job, string> = {
    recording: session ? hex(session.held.client.secretKey, 12) : '',
    site: session ? hex(session.held.certPrivate, 12) : '',
    token: session ? hex(session.held.tokenPrivate, 12) : '',
  };
  const jobPq: Record<Job, boolean> = { recording: KEX[setup.kex].pq, site: SIG[setup.cert].pq, token: SIG[setup.token].pq };
  const lostFor = (job: Job): string =>
    computer === 'quantum' && jobPq[job]
      ? { recording: 'The ML-KEM half has no known quantum attack, so the recording stays sealed.', site: 'ML-DSA has no known quantum attack. A browser rejects her.', token: 'ML-DSA has no known quantum attack. Her forgery is rejected.' }[job]
      : { recording: 'An ordinary computer cannot work out the private half. The recording stays sealed.', site: 'An ordinary computer cannot recover the certificate key. A browser rejects her.', token: 'An ordinary computer cannot recover the signing key. Her forgery is rejected.' }[job];
  /** Her working for each job: every value is the one actually computed, in the order she computed it. */
  const linesFor = (job: Job): Line[] => {
    if (!session || !result) return [];
    const quantum = computer === 'quantum';
    const stop = (text: string): Line => ({ text, ok: false });
    if (job === 'recording') {
      const lines: Line[] = [{ text: 'Public half, from the recording', value: hex(session.clientShare, 6) }];
      if (!quantum) return [...lines, stop('Private half: not found')];
      lines.push({ text: 'Private half, recovered', value: hex(session.held.client.secretKey, 6), ok: true });
      const derived = result.key.derivedSecret!;
      const matches = derived.length === session.sharedSecret.length && derived.every((b, i) => b === session.sharedSecret[i]);
      lines.push(matches ? { text: 'Secret re-derived: same as step 1', value: hex(derived, 6), ok: true } : { text: 'Secret re-derived: the ML-KEM half is missing', value: hex(derived, 6), ok: false });
      lines.push(result.key.decryptedLogin ? { text: 'AES-256-GCM opened the recording', value: `password=${stolen}`, ok: true } : stop('AES-256-GCM: wrong key, tag check failed'));
      return lines;
    }
    const key = job === 'site' ? session.certKey : session.tokenKey;
    const recovered = job === 'site' ? result.site.keyRecovered : result.token.keyRecovered;
    const accepted = job === 'site' ? result.site.accepted : result.token.accepted;
    const lines: Line[] = [{ text: job === 'site' ? 'Certificate public key' : 'Token public key, published', value: hex(publicBytes(key), 6) }];
    lines.push(recovered ? { text: 'Private key, recovered', value: hex(job === 'site' ? session.held.certPrivate : session.held.tokenPrivate, 6), ok: true } : { text: quantum ? 'Private key: no quantum attack on this' : 'Private key: not found', ok: false });
    lines.push(job === 'site' ? { text: 'Signed a new handshake' + (recovered ? '' : ' with a key of her own'), value: hex(result.site.signature, 6) } : { text: `Wrote a token for ${who}` + (recovered ? '' : ', signed with a key of her own'), value: hex(new TextEncoder().encode(result.token.forged), 6) });
    lines.push({ text: job === 'site' ? 'Browser checked it with the real public key' : 'Site checked it with its real public key', value: accepted ? 'accepted' : 'rejected', ok: accepted });
    return lines;
  };
  const wonText = (job: Job): string =>
    ({
      recording: `She re-derived the key and opened the recording. Your password: ${stolen}.`,
      site: 'She recovered the certificate’s private key, so she can sign as the site. A browser accepts her.',
      token: `She recovered the signing key and wrote a token that says she is ${who}. The site accepts it.`,
    })[job];

  return (
    <section className="sheet">
      <div className="lab">
        <header className="lab-head">
          <h1>The login lab</h1>
          <p className="sub">Set what the site uses, log in with a password you make up, and watch the three things that protect it. Then be the attacker and see what a quantum computer changes. Every value is computed in your browser as you log in.</p>
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
              <label>
                <span>Username</span>
                <input type="text" aria-label="Username: make one up" placeholder="make one up" value={login.username} maxLength={LOGIN_LIMITS.username} onChange={(e) => setLogin({ ...login, username: e.target.value })} spellCheck={false} autoCapitalize="none" autoComplete="off" />
              </label>
              <label>
                <span>Password</span>
                <input type="password" aria-label="Password: make one up" placeholder="make one up" value={login.password} maxLength={LOGIN_LIMITS.password} onChange={(e) => setLogin({ ...login, password: e.target.value })} autoComplete="off" />
              </label>
              <button type="submit" className="primary">
                Log in
              </button>
            </form>
          )}
        </div>

        <ol className="processes" aria-label="What happens when you log in">
          <li>
            <Process n={1} title="Key exchange" live={stage >= 1} pq={KEX[setup.kex].pq} scene={<ProcessScene step="kex" pq={KEX[setup.kex].pq} live={stage >= 1} />} sub={<>{KEX[setup.kex].name} <Tag kind={KEX[setup.kex].pq ? 'PQC' : 'classical'} /></>}>
              {session && (
                <>
                  <Value label="Browser’s public half" bytes={hex(session.clientShare, 7)} note="sent in the open" />
                  <Value label="Shared secret" bytes={hex(session.sharedSecret, 7)} note="never sent" pq={KEX[setup.kex].pq} />
                  <Value label="Your login, encrypted" bytes={hex(session.loginRecord.subarray(5), 8)} note="on the wire" />
                </>
              )}
            </Process>
          </li>
          <li>
            <Process n={2} title="Site proves who it is" live={stage >= 2} pq={SIG[setup.cert].pq} scene={<ProcessScene step="cert" pq={SIG[setup.cert].pq} live={stage >= 2} />} sub={<>{SIG[setup.cert].name} <Tag kind={SIG[setup.cert].pq ? 'PQC' : 'classical'} /></>}>
              {session && (
                <>
                  <Value label="Signature over the handshake" bytes={hex(session.certificateVerify, 8)} note={`${session.certificateVerify.length.toLocaleString('en-US')} bytes`} pq={SIG[setup.cert].pq} />
                  <p className={`check ${session.certificateVerifyValid ? 'ok' : 'bad'}`}>{session.certificateVerifyValid ? 'This is the real payroll.example' : 'Did not verify'}</p>
                </>
              )}
            </Process>
          </li>
          <li>
            <Process n={3} title="Sign-in token" live={stage >= 3} pq={SIG[setup.token].pq} scene={<ProcessScene step="token" pq={SIG[setup.token].pq} live={stage >= 3} />} sub={<>{SIG[setup.token].name} <Tag kind={SIG[setup.token].pq ? 'PQC' : 'classical'} /></>}>
              {session && (
                <>
                  <Value label={`Token for ${who}`} bytes={hex(new TextEncoder().encode(session.token), 8)} note={`${session.token.length.toLocaleString('en-US')} bytes`} pq={SIG[setup.token].pq} />
                  <p className={`check ${session.tokenValid ? 'ok' : 'bad'}`}>{session.tokenValid ? 'Only the site can make one' : 'Did not verify'}</p>
                </>
              )}
            </Process>
          </li>
        </ol>

        {session && stage >= 4 && (
          <div className="attacker">
            <header className="attacker-head">
              <div>
                <h2>Be the attacker</h2>
                <p className="sub">{computer ? 'She copied everything that crossed the network. Each job runs in turn.' : 'She copied everything that crossed the network. Pick her computer to run the three attempts.'}</p>
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
                  <AttackRow n={i + 1} job={job} title={title} computer={computer} runKey={runKey} startAt={startAt[job]} won={wonFor[job]} target={targetFor[job]} pq={jobPq[job]} wonText={wonText(job)} lostText={lostFor(job)} lines={linesFor(job)} />
                </li>
              ))}
            </ol>
            <p className="attacker-foot">
              Every outcome is a real decryption or signature check on the values from your login; only the quantum computer is simulated, by handing her the private key it would compute. The cipher itself is never the
              target: what falls is the public-key step around it. <a href={href('')}>Scan a real sign-in page</a> to see which of these a site is exposed to.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
