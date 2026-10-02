import { useEffect, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { generateKey, signJwt, verifyJwt } from '../crypto/jws.ts';
import type { LabKey } from '../crypto/jws.ts';
import { Stage } from './Stage.tsx';
import type { Packet, Spot } from './Stage.tsx';
import { TokenView } from './TokenView.tsx';

/**
 * Two scenes on the same three machines, stepped through at the reader's pace:
 *   1. Alice logs in.
 *   2. Mallory, an attacker, tries to get in as Alice without the password.
 *
 * Colour is fixed: green is the login service's secret key and any signature
 * made with it, blue is the public key, red is anything the attacker makes.
 *
 * A signature is drawn as a row of tall and short bars. The public key
 * "expects" a particular row; checking a signature is lining the two up.
 * The real signatures and checks run underneath (ES256 or ML-DSA-65); with
 * today's signature and a quantum computer, the page reveals the service's
 * actual secret key, which is what Shor's algorithm would compute.
 */
const ISSUER = 'https://login.example';
const APP = 'payroll';
const CRACK_MS = 3600;

type Signature = 'old' | 'new';
const ALG = { old: 'ES256', new: 'ML-DSA-65' } as const;

/** The bar patterns: what the login service's key produces, and what a made-up key produces. */
const REAL = [1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1];
const FAKE = [0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0];

interface Keys {
  service: Record<Signature, LabKey>;
  mallory: Record<Signature, LabKey>;
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

/* ---------- Drawn pieces ---------- */

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

/** A signature, drawn as bars. `against` colours each bar by whether it matches the expected row. */
function Bars({ pattern, tone, against }: { pattern: number[]; tone: 'secret' | 'attacker' | 'public'; against?: number[] }) {
  return (
    <span className={`bars ${tone}`} aria-hidden="true">
      {pattern.map((bit, i) => (
        <i key={i} className={`${bit ? 'hi' : 'lo'} ${against ? (against[i] === bit ? 'match' : 'miss') : ''}`} />
      ))}
    </span>
  );
}

type Signed = 'real' | 'fake' | undefined;

/** A login token. Its signature is green if made with the service's secret key, red if made with any other key. */
function Token({ signed, forged }: { signed: Signed; forged?: boolean }) {
  return (
    <span className={`minitoken ${forged ? 'forged' : ''}`}>
      <b>Login token</b>
      <span>“This is Alice”</span>
      {signed ? (
        <Bars pattern={signed === 'real' ? REAL : FAKE} tone={signed === 'real' ? 'secret' : 'attacker'} />
      ) : (
        <span className="unsigned">not signed yet</span>
      )}
    </span>
  );
}

/** Signing, drawn: an unsigned token and a key go in, a signed token comes out. */
function SignBench({ keyKind, keyLabel, result, forged }: { keyKind: 'secret' | 'attacker'; keyLabel: string; result: 'real' | 'fake'; forged?: boolean }) {
  return (
    <div className="bench-op">
      <Token signed={undefined} forged={forged} />
      <span className="op">+</span>
      <Key kind={keyKind}>{keyLabel}</Key>
      <span className="op">=</span>
      <Token signed={result} forged={forged} />
    </div>
  );
}

/** Checking, drawn: the token's signature lined up against what the public key expects. */
function CheckBench({ signed }: { signed: 'real' | 'fake' }) {
  const fits = signed === 'real';
  return (
    <div className="bench-check">
      <div>
        <span>Signature on the token</span>
        <Bars pattern={signed === 'real' ? REAL : FAKE} tone={fits ? 'secret' : 'attacker'} against={REAL} />
      </div>
      <div>
        <span>What the public key expects</span>
        <Bars pattern={REAL} tone="public" />
      </div>
    </div>
  );
}

function MachineHead({ icon, name, owner }: { icon: 'laptop' | 'server'; name: string; owner: string }) {
  return (
    <header className="machine-head">
      <svg viewBox="0 0 24 24" aria-hidden="true">
        {icon === 'laptop' ? <path d="M5 5h14v10H5zM2 19h20" /> : <path d="M4 4h16v6H4zM4 14h16v6H4zM7 7h.01M7 17h.01" />}
      </svg>
      <div>
        <b>{name}</b>
        <span>{owner}</span>
      </div>
    </header>
  );
}

function Holds({ locked, children, note }: { locked?: boolean; children: ReactNode; note: string }) {
  return (
    <div className={`holds ${locked ? 'locked' : ''}`}>
      {children}
      <span>{note}</span>
    </div>
  );
}

function LoginService({ signing }: { signing?: boolean }) {
  return (
    <>
      <MachineHead icon="server" name="Login service" owner="run by Google, or your company" />
      <Holds locked note="never leaves this server">
        <Key kind="secret">Secret key</Key>
      </Holds>
      <Holds note="published for anyone to copy">
        <Key kind="public">Public key</Key>
      </Holds>
      {signing && <SignBench keyKind="secret" keyLabel="Secret key" result="real" />}
    </>
  );
}

function PayrollApp({ checking, fooled }: { checking?: 'real' | 'fake'; fooled?: boolean }) {
  return (
    <>
      <MachineHead icon="server" name="Payroll app" owner="the app being logged in to" />
      <Holds note="a copy, to check signatures with">
        <Key kind="public">Public key</Key>
      </Holds>
      {checking && (
        <>
          <CheckBench signed={checking} />
          <p className={`check ${checking === 'real' ? (fooled ? 'fooled' : 'fits') : 'refused'}`}>
            {checking === 'real' ? 'It fits. Let them in.' : 'It doesn’t fit. Refused.'}
          </p>
        </>
      )}
    </>
  );
}

/** A clickable timeline: the reader moves through the steps at their own pace. */
function Timeline({
  titles,
  at,
  onGo,
  caption,
  idle,
}: {
  titles: string[];
  at: number;
  onGo: (step: number) => void;
  caption: string;
  idle: string;
}) {
  const started = at > 0;
  return (
    <div className="timeline">
      <ol>
        {titles.map((title, i) => (
          <li key={title}>
            <button type="button" aria-current={i + 1 === at ? 'step' : undefined} disabled={!started} onClick={() => onGo(i + 1)}>
              <span>{i + 1}</span>
              {title}
            </button>
          </li>
        ))}
      </ol>
      <div className="timeline-now">
        <p aria-live="polite">{started ? caption : idle}</p>
        <div className="timeline-nav">
          <button type="button" disabled={at <= 1} onClick={() => onGo(at - 1)}>
            Back
          </button>
          <button type="button" className="primary" disabled={!started || at >= titles.length} onClick={() => onGo(at + 1)}>
            Next step
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * The attack on the key itself. When the key can be worked out, its real
 * characters lock in one at a time; when it can't, the search just churns.
 */
function Cracker({ target, succeeds, state }: { target: string; succeeds: boolean; state: 'idle' | 'running' | 'done' }) {
  const LENGTH = 22;
  const [text, setText] = useState('·'.repeat(LENGTH));
  const [locked, setLocked] = useState(0);

  useEffect(() => {
    if (state === 'idle') {
      setText('·'.repeat(LENGTH));
      setLocked(0);
      return;
    }
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const finish = () => {
      setLocked(succeeds ? LENGTH : 0);
      setText(succeeds ? target.slice(0, LENGTH) : '?'.repeat(LENGTH));
    };
    if (state === 'done' || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return finish();

    const started = performance.now();
    const timer = window.setInterval(() => {
      const progress = Math.min(1, (performance.now() - started) / CRACK_MS);
      const fixed = succeeds ? Math.floor(progress * LENGTH) : 0;
      let next = target.slice(0, fixed);
      for (let i = fixed; i < LENGTH; i++) next += alphabet[Math.floor(Math.random() * alphabet.length)];
      setLocked(fixed);
      setText(next);
    }, 70);
    return () => window.clearInterval(timer);
  }, [state, succeeds, target]);

  return (
    <span className={`cracker ${state === 'done' ? (succeeds ? 'found' : 'failed') : ''}`} aria-hidden="true">
      <span className="locked">{text.slice(0, locked)}</span>
      <span>{text.slice(locked)}</span>
    </span>
  );
}

/* ---------- The section ---------- */

interface Attack {
  step: number;
  token: string;
  accepted: boolean;
  signature: Signature;
  quantum: boolean;
  /** Has the key search finished? It keeps its result if the reader steps back to it. */
  searched: boolean;
}

const LOGIN_TITLES = ['Password sent', 'Token signed', 'Token returned', 'Token handed over', 'Signature checked'];
const LOGIN_CAPTIONS = [
  'Alice’s password goes to the login service, not to the app.',
  'The login service checks the password, writes a token saying “this is Alice”, and signs it with its secret key. The key itself stays put.',
  'The signed token comes back to Alice’s browser.',
  'Her browser hands the token to the Payroll app.',
  'The app lines the signature up against its copy of the public key. Every bar matches, so Alice is in.',
];
const ATTACK_TITLES = ['Public key copied', 'Secret key attacked', 'Token forged', 'Token sent', 'Signature checked'];

export function LoginScene() {
  const [keys, setKeys] = useState<Keys>();
  const [email, setEmail] = useState('alice@example.com');
  const [password, setPassword] = useState('correct-horse');
  const [login, setLogin] = useState<{ step: number; token: string }>();
  const [signature, setSignature] = useState<Signature>('old');
  const [quantum, setQuantum] = useState(false);
  const [attack, setAttack] = useState<Attack>();
  const [found, setFound] = useState<Record<string, boolean>>({});

  useEffect(() => {
    makeKeys().then(setKeys);
  }, []);

  async function onLogin(event: FormEvent) {
    event.preventDefault();
    if (!keys) return;
    const { token } = await makeToken(keys.service.old, keys, 'old');
    setLogin({ step: 1, token });
  }

  async function startAttack() {
    if (!keys) return;
    const cracked = quantum && signature === 'old';
    const { token, accepted } = await makeToken(cracked ? keys.service.old : keys.mallory[signature], keys, signature);
    setAttack({ step: 1, token, accepted, signature, quantum, searched: false });
  }

  function goAttack(step: number) {
    if (!attack) return;
    // Leaving the search step counts as letting it finish.
    setAttack({ ...attack, step, searched: attack.searched || step > 2 });
    if (step === 5) setFound((f) => ({ ...f, [`${attack.signature}-${attack.quantum}`]: attack.accepted }));
  }

  // The key search runs once, the first time step 2 is shown.
  const searching = attack?.step === 2 && !attack.searched;
  useEffect(() => {
    if (!searching) return;
    const timer = window.setTimeout(() => setAttack((a) => (a ? { ...a, searched: true } : a)), CRACK_MS + 200);
    return () => window.clearTimeout(timer);
  }, [searching]);

  /* ----- Scene 1 ----- */
  const ls = login?.step ?? 0;
  const loginPacket: Packet | undefined =
    ls === 1
      ? { id: 'password', from: 'left', at: 'service', content: <span className="secretword">password</span> }
      : ls === 3
        ? { id: 'token-back', from: 'service', at: 'left', content: <Token signed="real" /> }
        : ls === 4
          ? { id: 'token-on', from: 'left', at: 'app', content: <Token signed="real" /> }
          : undefined;
  const loginBusy: Spot | undefined = ls === 2 ? 'service' : ls === 5 ? 'app' : undefined;
  const loggedIn = ls === 5;

  /* ----- Scene 2 ----- */
  const as = attack?.step ?? 0;
  const cracked = attack ? attack.quantum && attack.signature === 'old' : false;
  const forgedWith = cracked ? 'real' : 'fake';
  const attackPacket: Packet | undefined =
    as === 1
      ? { id: 'copy', from: 'service', at: 'left', content: <Key kind="public">Public key</Key> }
      : as === 4
        ? { id: 'forged', from: 'left', at: 'app', content: <Token signed={forgedWith} forged /> }
        : undefined;
  const attackBusy: Spot | undefined = as === 5 ? 'app' : as === 2 || as === 3 ? 'left' : undefined;
  const whyNot = attack
    ? attack.signature === 'new'
      ? 'No known method works on this kind of key' + (attack.quantum ? ', even on a quantum computer.' : '.')
      : 'A normal computer would need billions of years.'
    : '';
  const attackCaptions = [
    'Mallory copies the login service’s public key. Anyone can: it is published.',
    attack?.searched
      ? cracked
        ? 'Her quantum computer worked the secret key out from the public one. The login service was never touched.'
        : `She tried to work the secret key out from the public one. ${whyNot}`
      : 'She tries to work the secret key out from the public one…',
    cracked
      ? 'She writes a token saying she is Alice and signs it with the real secret key. The signature is identical to a genuine one.'
      : 'Without the secret key, she signs a token with a key she made up. The signature comes out different.',
    'She skips the login page and sends the token straight to the Payroll app.',
    attack?.accepted
      ? 'The app lines the signature up against the public key. Every bar matches. It can’t tell this token from a real one, and Mallory is in as Alice.'
      : 'The app lines the signature up against the public key. The bars don’t match, so it refuses.',
  ];
  const searchState = as < 2 ? 'idle' : attack?.searched ? 'done' : 'running';

  return (
    <section className="block" id="how">
      <h2>What that result means</h2>

      {/* ---------- Scene 1 ---------- */}
      <div className="act">
        <h3 className="act-title">Alice logs in to Payroll</h3>
        <Stage
          busy={loginBusy}
          packet={loginPacket}
          left={
            <>
              <MachineHead icon="laptop" name="Alice’s computer" owner="her browser" />
              <div className="screen">
                {loggedIn ? (
                  <div className="app-home">
                    <b className="success">Login successful</b>
                    <button type="button" onClick={() => setLogin(undefined)}>
                      Log out
                    </button>
                  </div>
                ) : (
                  <form className="login-form" onSubmit={onLogin}>
                    <b>Payroll</b>
                    <label>
                      Email
                      <input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" />
                    </label>
                    <label>
                      Password
                      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />
                    </label>
                    <button type="submit" className="primary" disabled={!keys || ls > 0}>
                      {ls > 0 ? 'Logging in…' : 'Log in'}
                    </button>
                  </form>
                )}
              </div>
            </>
          }
          service={<LoginService signing={ls === 2} />}
          app={<PayrollApp checking={ls === 5 ? 'real' : undefined} />}
        />
        <Timeline
          titles={LOGIN_TITLES}
          at={ls}
          onGo={(step) => login && setLogin({ ...login, step })}
          caption={LOGIN_CAPTIONS[ls - 1] ?? ''}
          idle="Press Log in, then step through what happens."
        />
        {loggedIn && login && (
          <details>
            <summary>See the real token</summary>
            <TokenView token={login.token} />
          </details>
        )}
      </div>

      {/* ---------- Scene 2 ---------- */}
      <div className="act attack">
        <h3 className="act-title">Mallory, an attacker, wants in as Alice. She doesn’t have the password.</h3>
        <p className="act-plan">
          The app only checks the signature. If Mallory can make a signature that fits, she doesn’t need the password.
          For that she needs the secret key, which is locked inside the login service.
        </p>

        <div className="setup">
          <div className="switch-row">
            <span>The login service signs with</span>
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
          <button type="button" className="danger" disabled={!keys} onClick={() => void startAttack()}>
            {attack ? 'Start a new attack' : 'Start the attack'}
          </button>
        </div>

        <Stage
          tone="attack"
          busy={attackBusy}
          packet={attackPacket}
          left={
            <>
              <MachineHead
                icon="laptop"
                name="Mallory’s computer"
                owner={(attack?.quantum ?? quantum) ? 'a quantum computer' : 'a normal computer'}
              />
              <div className="bench">
                <div className={`bench-row ${as >= 2 ? 'on' : ''}`}>
                  <span>Working the secret key out from the public key</span>
                  {as >= 2 && <Key kind="public">Public key</Key>}
                  <Cracker target={keys?.oldSecret ?? ''} succeeds={cracked} state={searchState} />
                  {attack?.searched &&
                    (cracked ? <Key kind="secret">Secret key, worked out</Key> : <em className="fail">No key. {whyNot}</em>)}
                </div>
                {as >= 3 && (
                  <div className="bench-row on">
                    <span>Forging a token</span>
                    <SignBench
                      keyKind={cracked ? 'secret' : 'attacker'}
                      keyLabel={cracked ? 'Secret key' : 'Made-up key'}
                      result={forgedWith}
                      forged
                    />
                  </div>
                )}
                {as === 5 && attack && (
                  <div className="bench-row on">
                    <span>Her screen</span>
                    {attack.accepted ? (
                      <strong className="got-in">Login successful. She is in as Alice.</strong>
                    ) : (
                      <strong>Access denied</strong>
                    )}
                  </div>
                )}
              </div>
            </>
          }
          service={<LoginService />}
          app={<PayrollApp checking={as === 5 ? forgedWith : undefined} fooled={as === 5 && attack?.accepted} />}
        />

        <Timeline
          titles={ATTACK_TITLES}
          at={as}
          onGo={goAttack}
          caption={attackCaptions[as - 1] ?? ''}
          idle="Choose a signature and a computer, start the attack, then step through it."
        />

        <table className="outcomes">
          <caption>Attacks you’ve run</caption>
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
    </section>
  );
}
