import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { base64urlToBytes } from '@pq-oidc/token-kit/base64url';
import { generateKey, signJwt, verifyJwt } from '../crypto/jws.ts';
import type { LabKey } from '../crypto/jws.ts';
import { TokenView } from './TokenView.tsx';

/**
 * A login you already know (a form, a button) next to what happens behind it.
 * Then the same scene from an attacker's side, with two switches to play with:
 * which signature the login service uses, and whether the attacker has a
 * quantum computer.
 *
 * Every signature and check is real. The quantum computer is the one simulated
 * part: with the old signature we hand the attacker the service's secret key,
 * which is what Shor's algorithm would compute from the public key.
 */
const ISSUER = 'https://login.example';
const APP = 'payroll';
const STEP_MS = 900;

type Signature = 'old' | 'new';
type Who = 'alice' | 'mallory';
const ALG = { old: 'ES256', new: 'ML-DSA-65' } as const;

interface Keys {
  service: Record<Signature, LabKey>;
  mallory: Record<Signature, LabKey>;
}

interface Run {
  who: Who;
  signature: Signature;
  quantum: boolean;
  token: string;
  accepted: boolean;
  /** 1 to 4: how far the behind-the-scenes story has played. */
  stage: number;
}

async function makeKeys(): Promise<Keys> {
  const [oldKey, newKey, malloryOld, malloryNew] = await Promise.all([
    generateKey('ES256', 'login-service-2019'),
    generateKey('ML-DSA-65', 'login-service-2026'),
    generateKey('ES256', 'login-service-2019'), // Mallory copies the key names; they are public
    generateKey('ML-DSA-65', 'login-service-2026'),
  ]);
  return { service: { old: oldKey, new: newKey }, mallory: { old: malloryOld, new: malloryNew } };
}

async function signIn(keys: Keys, who: Who, signature: Signature, quantum: boolean) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: ISSUER, aud: APP, sub: 'alice', name: 'Alice Nakamura', iat: now, exp: now + 300 };
  const stolen = who === 'mallory' && quantum && signature === 'old';
  const key = who === 'alice' || stolen ? keys.service[signature] : keys.mallory[signature];
  const token = await signJwt(key, claims);
  const result = await verifyJwt(token, [keys.service.old.publicJwk, keys.service.new.publicJwk], {
    issuer: ISSUER,
    audience: APP,
    algorithms: [ALG[signature]],
  });
  return { token, accepted: result.ok };
}

function story(run: Run): string[] {
  if (run.who === 'alice') {
    return [
      'The login service checks your password.',
      'It writes a token saying who you are and signs it with its secret key.',
      'Your browser carries the token to the Payroll app.',
      'The app checks the signature against the login service’s public key. It matches.',
    ];
  }
  const stolen = run.quantum && run.signature === 'old';
  return [
    'Mallory skips the password and writes her own token saying she is Alice.',
    stolen
      ? 'Her quantum computer works out the login service’s secret key from its public key. She signs with it.'
      : run.quantum
        ? 'Her quantum computer gets nothing from the new public key. She signs with a key of her own.'
        : 'She can’t get the secret key, so she signs with a key of her own.',
    'She sends the token to the Payroll app.',
    run.accepted
      ? 'The signature matches. The app can’t tell this token from a real one.'
      : 'The signature doesn’t match the login service’s public key. The app refuses.',
  ];
}

function KeyIcon({ tone }: { tone: 'secret' | 'public' | 'stolen' }) {
  return (
    <svg className={`key-icon ${tone}`} viewBox="0 0 40 20" aria-hidden="true">
      <circle cx="9" cy="10" r="6" fill="none" strokeWidth="3" />
      <path d="M15 10h22M30 10v6M36 10v5" fill="none" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function LoginScene() {
  const [keys, setKeys] = useState<Keys>();
  const [signature, setSignature] = useState<Signature>('old');
  const [quantum, setQuantum] = useState(false);
  const [run, setRun] = useState<Run>();
  const [found, setFound] = useState<Record<string, boolean>>({});
  const [email, setEmail] = useState('alice@example.com');
  const [password, setPassword] = useState('correct-horse');
  const timers = useRef<number[]>([]);

  useEffect(() => {
    makeKeys().then(setKeys);
    return () => timers.current.forEach(window.clearTimeout);
  }, []);

  async function play(who: Who) {
    if (!keys) return;
    timers.current.forEach(window.clearTimeout);
    const { token, accepted } = await signIn(keys, who, signature, quantum);
    const next: Run = { who, signature, quantum, token, accepted, stage: 1 };
    setRun(next);
    timers.current = [2, 3, 4].map((stage, i) =>
      window.setTimeout(
        () => {
          setRun({ ...next, stage });
          if (stage === 4 && who === 'mallory') setFound((f) => ({ ...f, [`${signature}-${quantum}`]: accepted }));
        },
        (i + 1) * STEP_MS,
      ),
    );
  }

  function reset() {
    timers.current.forEach(window.clearTimeout);
    setRun(undefined);
  }

  function onLogin(event: FormEvent) {
    event.preventDefault();
    void play('alice');
  }

  const done = run?.stage === 4;
  const page = !run ? 'form' : !done ? (run.who === 'mallory' ? 'forging' : 'form') : run.accepted ? 'home' : 'denied';
  const lines = run ? story(run) : [];
  const stolenKey = quantum && signature === 'old';
  const signatureBytes = run ? base64urlToBytes(run.token.split('.')[2] ?? '').length : 0;

  return (
    <section className="block" id="how">
      <h2>What that result means</h2>
      <p className="sub">Log in on the left. The right side shows what your browser never shows you.</p>

      <div className="scene">
        {/* What you know: a login form in a browser. */}
        <div className={`browser ${run?.who === 'mallory' ? 'intruder' : ''}`}>
          <div className="browser-bar">
            <span className="browser-who">{run?.who === 'mallory' ? 'Mallory’s browser' : 'Your browser'}</span>
            <span className="browser-url">payroll.example/{page === 'home' ? 'home' : 'login'}</span>
          </div>
          <div className="browser-page">
            {page === 'form' && (
              <form className="login-form" onSubmit={onLogin}>
                <h3>Payroll</h3>
                <label>
                  Email
                  <input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" />
                </label>
                <label>
                  Password
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />
                </label>
                <button type="submit" className="primary" disabled={!keys || (run !== undefined && !done)}>
                  {run && !done ? 'Logging in…' : 'Log in'}
                </button>
                <p className="fine">A pretend account, filled in for you.</p>
              </form>
            )}
            {page === 'forging' && (
              <div className="app-denied">
                <h3>No form needed</h3>
                <p>Mallory skips the login page and sends the app a token she made herself.</p>
              </div>
            )}
            {page === 'home' && run && (
              <div className={`app-home ${run.who === 'mallory' ? 'breached' : ''}`}>
                {run.who === 'mallory' && <p className="breach">Mallory is in, as Alice.</p>}
                <h3>Welcome, Alice</h3>
                <ul>
                  <li>Next pay day: 15 October</li>
                  <li>Bank account ending 4471</li>
                  <li>Holiday left: 12 days</li>
                </ul>
                <button type="button" onClick={reset}>
                  Log out
                </button>
              </div>
            )}
            {page === 'denied' && (
              <div className="app-denied">
                <h3>Access denied</h3>
                <p>This login token isn’t genuine.</p>
                <button type="button" onClick={reset}>
                  Back
                </button>
              </div>
            )}
          </div>
        </div>

        {/* What you don't see: the token and the check. */}
        <div className="backstage" aria-live="polite">
          <div className="stations">
            <div className={`station ${run && run.stage <= 2 ? 'active' : ''}`}>
              <b>{run?.who === 'mallory' ? 'Mallory' : 'Login service'}</b>
              <span>
                <KeyIcon tone={run?.who === 'mallory' ? (stolenKey ? 'stolen' : 'public') : 'secret'} />
                {run?.who === 'mallory' ? (stolenKey ? 'has the secret key' : 'her own key') : 'secret key'}
              </span>
            </div>
            <div className="lane">
              {run && run.stage >= 2 && (
                <div className={`token-card ${run.stage >= 3 ? 'arrived' : ''} ${run.who === 'mallory' ? 'forged' : ''}`}>
                  <b>Login token</b>
                  <span>Alice Nakamura, for Payroll</span>
                  <span className={`sig ${run.signature}`}>
                    signature, {signatureBytes.toLocaleString('en-US')} bytes
                  </span>
                </div>
              )}
            </div>
            <div className={`station ${run && run.stage >= 3 ? 'active' : ''} ${done ? (run.accepted ? (run.who === 'mallory' ? 'fooled' : 'ok') : 'refused') : ''}`}>
              <b>Payroll app</b>
              <span>
                <KeyIcon tone="public" />
                public key
              </span>
              {done && <strong>{run.accepted ? 'Signature matches' : 'Signature doesn’t match'}</strong>}
            </div>
          </div>

          <ol className="story">
            {run ? (
              lines.map((line, i) => (
                <li key={line} className={i < run.stage ? 'shown' : ''}>
                  {line}
                </li>
              ))
            ) : (
              <li className="shown hint">Nothing has happened yet. Press Log in.</li>
            )}
          </ol>

          {run && done && (
            <details>
              <summary>See the real token</summary>
              <TokenView token={run.token} />
            </details>
          )}
        </div>
      </div>

      <div className="heist">
        <div className="heist-controls">
          <h3>Now try to get in without the password</h3>
          <div className="switch-row">
            <span>Login service signs with</span>
            <div className="seg" role="group" aria-label="Signature kind">
              <button type="button" aria-pressed={signature === 'old'} onClick={() => setSignature('old')}>
                Today’s signature
              </button>
              <button type="button" aria-pressed={signature === 'new'} onClick={() => setSignature('new')}>
                Quantum-proof signature
              </button>
            </div>
          </div>
          <div className="switch-row">
            <span>Mallory has</span>
            <div className="seg" role="group" aria-label="Attacker's computer">
              <button type="button" aria-pressed={!quantum} onClick={() => setQuantum(false)}>
                A normal computer
              </button>
              <button type="button" aria-pressed={quantum} onClick={() => setQuantum(true)}>
                A quantum computer
              </button>
            </div>
          </div>

          {/* The reason, drawn: can the secret key be worked out from the public one? */}
          <div className={`keyflow ${quantum ? (signature === 'old' ? 'broken' : 'holds') : 'idle'}`}>
            <span className="kf-key">
              <KeyIcon tone="public" />
              public key
            </span>
            <span className="kf-arrow">{quantum ? 'quantum computer' : 'normal computer'}</span>
            <span className="kf-key">
              {stolenKey ? (
                <>
                  <KeyIcon tone="stolen" />
                  secret key, worked out
                </>
              ) : (
                <>no secret key</>
              )}
            </span>
          </div>

          <button type="button" className="primary" disabled={!keys || (run !== undefined && !done)} onClick={() => void play('mallory')}>
            Break in as Alice
          </button>
        </div>

        <table className="outcomes">
          <caption>What you’ve found so far</caption>
          <thead>
            <tr>
              <td />
              <th scope="col">Normal computer</th>
              <th scope="col">Quantum computer</th>
            </tr>
          </thead>
          <tbody>
            {(['old', 'new'] as const).map((s) => (
              <tr key={s}>
                <th scope="row">{s === 'old' ? 'Today’s signature' : 'Quantum-proof signature'}</th>
                {[false, true].map((q) => {
                  const outcome = found[`${s}-${q}`];
                  return (
                    <td key={String(q)} className={outcome === undefined ? 'unknown' : outcome ? 'in' : 'out'}>
                      {outcome === undefined ? 'Not tried' : outcome ? 'Got in' : 'Kept out'}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="fine">
        The signatures and checks here are real. The quantum computer is simulated: none is big enough yet, so the
        page hands Mallory the secret key it would work out.
      </p>
    </section>
  );
}
