import { useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { generateKey, signJwt, verifyJwt } from '../crypto/jws.ts';
import type { LabKey } from '../crypto/jws.ts';
import { TokenView } from './TokenView.tsx';

/**
 * Two acts, drawn as four-frame strips that stay on screen:
 *   1. Alice logs in. A familiar form on the left, what happens behind it on the right.
 *   2. Mallory, an attacker, tries to get in as Alice without the password.
 *
 * Colour is fixed throughout: green is the login service's secret key (and
 * anything signed with it), blue is the public key anyone can copy, red is
 * anything the attacker makes.
 *
 * Every signature and check is real. The quantum computer is the one simulated
 * part: for today's signature we reveal the service's actual secret key, which
 * is what Shor's algorithm would compute from the public key.
 */
const ISSUER = 'https://login.example';
const APP = 'payroll';
const FRAME_MS = 1800;
const CRACK_MS = 3400;

type Signature = 'old' | 'new';
const ALG = { old: 'ES256', new: 'ML-DSA-65' } as const;

interface Keys {
  service: Record<Signature, LabKey>;
  mallory: Record<Signature, LabKey>;
  /** The service's real ES256 secret key, shown when the quantum computer "finds" it. */
  oldSecret: string;
}

async function makeKeys(): Promise<Keys> {
  const [oldKey, newKey, malloryOld, malloryNew] = await Promise.all([
    generateKey('ES256', 'login-service-2019'),
    generateKey('ML-DSA-65', 'login-service-2026'),
    generateKey('ES256', 'login-service-2019'), // Mallory reuses the key names; they are public
    generateKey('ML-DSA-65', 'login-service-2026'),
  ]);
  const jwk = 'privateKey' in oldKey ? await crypto.subtle.exportKey('jwk', oldKey.privateKey) : {};
  return { service: { old: oldKey, new: newKey }, mallory: { old: malloryOld, new: malloryNew }, oldSecret: jwk.d ?? '' };
}

async function makeToken(key: LabKey, keys: Keys, signature: Signature) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: ISSUER, aud: APP, sub: 'alice', name: 'Alice Nakamura', iat: now, exp: now + 300 };
  const token = await signJwt(key, claims);
  const result = await verifyJwt(token, [keys.service.old.publicJwk, keys.service.new.publicJwk], {
    issuer: ISSUER,
    audience: APP,
    algorithms: [ALG[signature]],
  });
  return { token, accepted: result.ok };
}

/* ---------- Small drawn pieces ---------- */

function Key({ kind, children }: { kind: 'secret' | 'public' | 'attacker'; children: ReactNode }) {
  return (
    <span className={`keytag ${kind}`}>
      <svg viewBox="0 0 40 20" aria-hidden="true">
        <circle cx="9" cy="10" r="6" strokeWidth="3" />
        <path d="M15 10h22M30 10v6M36 10v5" fill="none" strokeWidth="3" strokeLinecap="round" />
      </svg>
      {children}
    </span>
  );
}

function Person({ who }: { who: 'alice' | 'mallory' }) {
  return (
    <span className={`person ${who}`}>
      <i aria-hidden="true">{who === 'alice' ? 'A' : 'M'}</i>
      {who === 'alice' ? 'Alice' : 'Mallory'}
    </span>
  );
}

function Box({ children }: { children: ReactNode }) {
  return <span className="sysbox">{children}</span>;
}

/** A login token, with its signature drawn in the colour of the key that made it. */
function MiniToken({ signedWith, forged }: { signedWith: 'secret' | 'attacker'; forged?: boolean }) {
  return (
    <span className={`minitoken ${forged ? 'forged' : ''}`}>
      <b>Login token</b>
      <span>“This is Alice”</span>
      <span className={`strip ${signedWith}`}>signature</span>
    </span>
  );
}

const Arrow = ({ label }: { label?: string }) => <span className="arrow">{label}</span>;

function Frame({ n, shown, title, children }: { n: number; shown: boolean; title: string; children: ReactNode }) {
  return (
    <li className={`frame ${shown ? 'shown' : ''}`}>
      <span className="frame-n">{n}</span>
      <div className="frame-pic">{children}</div>
      <p>{title}</p>
    </li>
  );
}

/**
 * The attack on the key itself. When the key can be worked out, its real
 * characters lock in one at a time; when it can't, the search just churns.
 */
function Cracker({ target, succeeds, running, done }: { target: string; succeeds: boolean; running: boolean; done: boolean }) {
  const LENGTH = 24;
  const [text, setText] = useState('·'.repeat(LENGTH));
  const [locked, setLocked] = useState(0);

  useEffect(() => {
    if (!running && !done) return;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const finish = () => {
      setLocked(succeeds ? LENGTH : 0);
      setText(succeeds ? target.slice(0, LENGTH) : '?'.repeat(LENGTH));
    };
    if (done || reduced) return finish();

    const started = performance.now();
    const timer = window.setInterval(() => {
      const progress = Math.min(1, (performance.now() - started) / (CRACK_MS - 400));
      const fixed = succeeds ? Math.floor(progress * LENGTH) : 0;
      let next = target.slice(0, fixed);
      for (let i = fixed; i < LENGTH; i++) next += alphabet[Math.floor(Math.random() * alphabet.length)];
      setLocked(fixed);
      setText(next);
      if (progress >= 1) {
        window.clearInterval(timer);
        finish();
      }
    }, 70);
    return () => window.clearInterval(timer);
  }, [running, done, succeeds, target]);

  return (
    <span className={`cracker ${done ? (succeeds ? 'found' : 'failed') : ''}`} aria-hidden="true">
      <span className="locked">{text.slice(0, locked)}</span>
      <span>{text.slice(locked)}</span>
    </span>
  );
}

/* ---------- The section ---------- */

export function LoginScene() {
  const [keys, setKeys] = useState<Keys>();
  const [email, setEmail] = useState('alice@example.com');
  const [password, setPassword] = useState('correct-horse');

  // Act 1: Alice
  const [login, setLogin] = useState<{ frame: number; token: string }>();
  // Act 2: Mallory
  const [signature, setSignature] = useState<Signature>('old');
  const [quantum, setQuantum] = useState(false);
  const [attack, setAttack] = useState<{ frame: number; token: string; accepted: boolean; signature: Signature; quantum: boolean }>();
  const [found, setFound] = useState<Record<string, boolean>>({});
  const timers = useRef<number[]>([]);

  useEffect(() => {
    makeKeys().then(setKeys);
    return () => timers.current.forEach(window.clearTimeout);
  }, []);

  function schedule(steps: [delay: number, run: () => void][]) {
    timers.current.forEach(window.clearTimeout);
    let at = 0;
    timers.current = steps.map(([delay, run]) => window.setTimeout(run, (at += delay)));
  }

  async function onLogin(event: FormEvent) {
    event.preventDefault();
    if (!keys) return;
    const { token } = await makeToken(keys.service.old, keys, 'old');
    setLogin({ frame: 1, token });
    schedule([2, 3, 4].map((frame) => [FRAME_MS, () => setLogin({ frame, token })]));
  }

  async function startAttack() {
    if (!keys) return;
    const cracked = quantum && signature === 'old';
    const key = cracked ? keys.service.old : keys.mallory[signature];
    const { token, accepted } = await makeToken(key, keys, signature);
    const run = { token, accepted, signature, quantum };
    setAttack({ ...run, frame: 1 });
    schedule([
      [FRAME_MS, () => setAttack({ ...run, frame: 2 })],
      [CRACK_MS, () => setAttack({ ...run, frame: 3 })],
      [FRAME_MS, () => setAttack({ ...run, frame: 4 })],
      [FRAME_MS, () => {
        setAttack({ ...run, frame: 5 });
        setFound((f) => ({ ...f, [`${signature}-${quantum}`]: accepted }));
      }],
    ]);
  }

  const loggedIn = login?.frame === 4;
  const loggingIn = login !== undefined && !loggedIn;
  const attacking = attack !== undefined && attack.frame < 5;
  const cracked = attack ? attack.quantum && attack.signature === 'old' : false;
  const crackFail = attack
    ? attack.signature === 'new'
      ? attack.quantum
        ? 'No known method works on this key, even for a quantum computer.'
        : 'No known method works on this key.'
      : 'A normal computer would need billions of years.'
    : '';

  return (
    <section className="block" id="how">
      <h2>What that result means</h2>

      <ul className="colour-key">
        <li>
          <Key kind="secret">Secret key</Key> Only the login service has it. It signs every login.
        </li>
        <li>
          <Key kind="public">Public key</Key> Published. Apps use it to check signatures. Anyone can copy it.
        </li>
      </ul>

      {/* ---------- Act 1 ---------- */}
      <div className="act">
        <h3 className="act-title">
          <Person who="alice" /> logs in to Payroll
        </h3>
        <div className="scene">
          <div className="browser">
            <div className="browser-bar">
              <span className="browser-who">Alice’s browser</span>
              <span className="browser-url">payroll.example/{loggedIn ? 'home' : 'login'}</span>
            </div>
            <div className="browser-page">
              {loggedIn ? (
                <div className="app-home">
                  <h3>Welcome, Alice</h3>
                  <ul>
                    <li>Next pay day: 15 October</li>
                    <li>Bank account ending 4471</li>
                    <li>Holiday left: 12 days</li>
                  </ul>
                  <button type="button" onClick={() => setLogin(undefined)}>
                    Log out
                  </button>
                </div>
              ) : (
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
                  <button type="submit" className="primary" disabled={!keys || loggingIn}>
                    {loggingIn ? 'Logging in…' : 'Log in'}
                  </button>
                </form>
              )}
            </div>
          </div>

          <ol className={`strip-frames ${login ? '' : 'waiting'}`} aria-live="polite">
            <Frame n={1} shown={(login?.frame ?? 0) >= 1} title="The login service checks Alice’s password.">
              <Person who="alice" />
              <Arrow label="password" />
              <Box>Login service</Box>
            </Frame>
            <Frame n={2} shown={(login?.frame ?? 0) >= 2} title="It writes a token and signs it with its secret key.">
              <Box>Login service</Box>
              <Key kind="secret">signs</Key>
              <MiniToken signedWith="secret" />
            </Frame>
            <Frame n={3} shown={(login?.frame ?? 0) >= 3} title="Alice’s browser carries the token to the app.">
              <MiniToken signedWith="secret" />
              <Arrow />
              <Box>Payroll app</Box>
            </Frame>
            <Frame n={4} shown={(login?.frame ?? 0) >= 4} title="The app checks the signature with the public key. It fits, so Alice is in.">
              <Box>Payroll app</Box>
              <Key kind="public">checks</Key>
              <span className="verdict yes">Signature fits</span>
            </Frame>
          </ol>
        </div>
        {loggedIn && (
          <details>
            <summary>See the real token</summary>
            <TokenView token={login.token} />
          </details>
        )}
      </div>

      {/* ---------- Act 2 ---------- */}
      <div className="act attack">
        <h3 className="act-title">
          <Person who="mallory" /> is an attacker. She wants in as Alice and doesn’t have the password.
        </h3>
        <p className="act-plan">
          Her plan: the app only checks the signature, so if she can make a signature that fits, she doesn’t need the
          password. For that she needs the secret key.
        </p>

        <div className="setup">
          <div className="switch-row">
            <span>The login service signs with</span>
            <div className="seg" role="group" aria-label="Signature kind">
              <button type="button" aria-pressed={signature === 'old'} disabled={attacking} onClick={() => setSignature('old')}>
                Today’s signature
              </button>
              <button type="button" aria-pressed={signature === 'new'} disabled={attacking} onClick={() => setSignature('new')}>
                Quantum-proof signature
              </button>
            </div>
          </div>
          <div className="switch-row">
            <span>Mallory has</span>
            <div className="seg" role="group" aria-label="Attacker's computer">
              <button type="button" aria-pressed={!quantum} disabled={attacking} onClick={() => setQuantum(false)}>
                A normal computer
              </button>
              <button type="button" aria-pressed={quantum} disabled={attacking} onClick={() => setQuantum(true)}>
                A quantum computer
              </button>
            </div>
          </div>
          <button type="button" className="danger" disabled={!keys || attacking} onClick={() => void startAttack()}>
            {attacking ? 'Attacking…' : 'Start the attack'}
          </button>
        </div>

        <div className="scene">
          <ol className={`strip-frames ${attack ? '' : 'waiting'}`} aria-live="polite">
            <Frame n={1} shown={(attack?.frame ?? 0) >= 1} title="She copies the login service’s public key. Anyone can.">
              <Box>Login service</Box>
              <Key kind="public">copy</Key>
              <Person who="mallory" />
            </Frame>
            <Frame
              n={2}
              shown={(attack?.frame ?? 0) >= 2}
              title={
                (attack?.frame ?? 0) >= 3
                  ? cracked
                    ? 'Her quantum computer works the secret key out from the public one.'
                    : `She tries to work the secret key out from it. ${crackFail}`
                  : 'She tries to work the secret key out from the public one…'
              }
            >
              <Key kind="public">in</Key>
              <Cracker
                target={keys?.oldSecret ?? ''}
                succeeds={cracked}
                running={attack?.frame === 2}
                done={(attack?.frame ?? 0) >= 3}
              />
              {(attack?.frame ?? 0) >= 3 &&
                (cracked ? <Key kind="secret">found</Key> : <span className="verdict no">No key</span>)}
            </Frame>
            <Frame
              n={3}
              shown={(attack?.frame ?? 0) >= 3}
              title={
                cracked
                  ? 'She signs a token saying she is Alice, with the real secret key.'
                  : 'She signs a token anyway, with a key she made herself.'
              }
            >
              <Person who="mallory" />
              <Key kind={cracked ? 'secret' : 'attacker'}>signs</Key>
              <MiniToken signedWith={cracked ? 'secret' : 'attacker'} forged />
            </Frame>
            <Frame
              n={4}
              shown={(attack?.frame ?? 0) >= 4}
              title={
                (attack?.frame ?? 0) >= 5
                  ? attack?.accepted
                    ? 'The signature fits. The app can’t tell this token from a real one.'
                    : 'The signature doesn’t fit the public key. The app refuses.'
                  : 'She sends it to the app, which checks the signature…'
              }
            >
              <Box>Payroll app</Box>
              <Key kind="public">checks</Key>
              {(attack?.frame ?? 0) >= 5 &&
                (attack?.accepted ? (
                  <span className="verdict breach">Signature fits</span>
                ) : (
                  <span className="verdict yes">Doesn’t fit</span>
                ))}
            </Frame>
          </ol>

          <div className="attack-side">
            <div className="browser intruder">
              <div className="browser-bar">
                <span className="browser-who">Mallory’s browser</span>
                <span className="browser-url">payroll.example/{attack?.frame === 5 && attack.accepted ? 'home' : 'login'}</span>
              </div>
              <div className="browser-page">
                {attack?.frame === 5 ? (
                  attack.accepted ? (
                    <div className="app-home breached">
                      <p className="breach">Mallory is in, as Alice.</p>
                      <h3>Welcome, Alice</h3>
                      <ul>
                        <li>Next pay day: 15 October</li>
                        <li>Bank account ending 4471</li>
                      </ul>
                    </div>
                  ) : (
                    <div className="app-denied">
                      <h3>Access denied</h3>
                      <p>This login token isn’t genuine.</p>
                    </div>
                  )
                ) : (
                  <p className="waiting-note">{attack ? 'Waiting for the app’s answer…' : 'Nothing sent yet.'}</p>
                )}
              </div>
            </div>

            <table className="outcomes">
              <caption>Attacks tried</caption>
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
                    <th scope="row">{s === 'old' ? 'Today’s signature' : 'Quantum-proof'}</th>
                    {[false, true].map((q) => {
                      const outcome = found[`${s}-${q}`];
                      return (
                        <td key={String(q)} className={outcome === undefined ? 'unknown' : outcome ? 'in' : 'out'}>
                          {outcome === undefined ? '?' : outcome ? 'Got in' : 'Kept out'}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <p className="fine">
          The quantum computer is simulated, since none is big enough yet: the page reveals the login service’s actual
          secret key, which is what one would compute. The signatures and the app’s checks are real.
        </p>
      </div>
    </section>
  );
}
