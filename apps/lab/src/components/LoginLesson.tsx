import { useEffect, useState } from 'react';
import { base64urlToBytes } from '@pq-oidc/token-kit/base64url';
import { generateKey, signJwt, verifyJwt } from '../crypto/jws.ts';
import type { LabKey, VerifyResult } from '../crypto/jws.ts';
import { TokenView } from './TokenView.tsx';

/**
 * Two steps of the lesson share one live login:
 *   "How would that work?"  sign in, forge a login, forge it with a quantum computer
 *   "What stops it?"        switch to the new signature and try the same attack
 *
 * Every signature and every check is real. The one simulated part is the
 * quantum computer: we hand the attacker the old secret key, which is exactly
 * what Shor's algorithm would compute from the public key.
 */
const ISSUER = 'https://login.example';
const APP = 'payroll';
type Signature = 'old' | 'new';
type Act = 'honest' | 'forged' | 'quantum';

interface Keys {
  service: Record<Signature, LabKey>;
  mallory: Record<Signature, LabKey>;
}

interface Attempt {
  act: Act;
  signature: Signature;
  signedBy: 'the login service' | 'Mallory';
  token: string;
  result: VerifyResult;
}

const ALG = { old: 'ES256', new: 'ML-DSA-65' } as const;

async function makeKeys(): Promise<Keys> {
  const [oldKey, newKey, malloryOld, malloryNew] = await Promise.all([
    generateKey('ES256', 'login-service-2019'),
    generateKey('ML-DSA-65', 'login-service-2026'),
    // Mallory labels her keys with the service's key names; the names are public anyway.
    generateKey('ES256', 'login-service-2019'),
    generateKey('ML-DSA-65', 'login-service-2026'),
  ]);
  return { service: { old: oldKey, new: newKey }, mallory: { old: malloryOld, new: malloryNew } };
}

async function attempt(keys: Keys, act: Act, signature: Signature): Promise<Attempt> {
  const now = Math.floor(Date.now() / 1000);
  const note = { iss: ISSUER, aud: APP, sub: 'alice', name: 'Alice Nakamura', iat: now, exp: now + 300 };
  // With the old signature, a quantum computer yields the service's own secret key.
  // With the new one there is nothing to recover, so Mallory is stuck with her own key.
  const stolen = act === 'quantum' && signature === 'old';
  const key = act === 'honest' || stolen ? keys.service[signature] : keys.mallory[signature];
  const token = await signJwt(key, note);
  const result = await verifyJwt(token, [keys.service.old.publicJwk, keys.service.new.publicJwk], {
    issuer: ISSUER,
    audience: APP,
    algorithms: [ALG[signature]],
  });
  return { act, signature, signedBy: act === 'honest' ? 'the login service' : 'Mallory', token, result };
}

function Note({ attempt: a }: { attempt: Attempt }) {
  const signatureBytes = base64urlToBytes(a.token.split('.')[2] ?? '').length;
  const accepted = a.result.ok;
  const fooled = accepted && a.act !== 'honest';
  return (
    <div className="exchange">
      <div className={`note ${a.act === 'honest' ? '' : 'forged'}`}>
        <p className="note-title">Login token</p>
        <dl>
          <dt>This person is</dt>
          <dd>Alice Nakamura</dd>
          <dt>Let them into</dt>
          <dd>Payroll</dd>
          <dt>Written by</dt>
          <dd>{a.signedBy}</dd>
          <dt>Signature</dt>
          <dd>
            <code>{(a.token.split('.')[2] ?? '').slice(0, 22)}…</code>
            {signatureBytes.toLocaleString('en-US')} bytes, the {a.signature === 'old' ? 'old' : 'new'} kind
          </dd>
        </dl>
      </div>
      <div className={`app-says ${fooled ? 'fooled' : accepted ? 'ok' : 'refused'}`} role="status">
        <span className="app-name">Payroll app</span>
        {accepted ? <b>“Welcome, Alice.”</b> : <b>“That signature isn’t the login service’s. No.”</b>}
        {fooled && <span>It can’t tell this token was forged.</span>}
      </div>
    </div>
  );
}

const EXPLAIN: Record<Signature, Record<Act, string>> = {
  old: {
    honest:
      'The login service signed the token with its secret key. The app checked the signature against the service’s public key, which anyone can look up.',
    forged: 'Mallory wrote her own token saying she’s Alice. She doesn’t have the secret key, so her signature doesn’t match.',
    quantum:
      'A quantum computer can work out the secret key from the public one. Mallory’s signature is now identical to the real thing, and she is in as Alice.',
  },
  new: {
    honest: 'Same login, new kind of signature. The app checks it the same way.',
    forged: 'Mallory tries again with her own key. Rejected, as before.',
    quantum:
      'The new signature rests on a maths problem quantum computers aren’t known to solve. There is no secret key to work out, so Mallory’s token is rejected.',
  },
};

export function LoginLesson() {
  const [keys, setKeys] = useState<Keys>();
  const [first, setFirst] = useState<Attempt>();
  const [second, setSecond] = useState<Attempt>();
  const [switched, setSwitched] = useState(false);

  useEffect(() => {
    makeKeys().then(async (k) => {
      setKeys(k);
      setFirst(await attempt(k, 'honest', 'old')); // start with a completed login on screen
    });
  }, []);

  const reached = (a: Attempt | undefined, act: Act) => a?.act === act;
  const run = (act: Act, signature: Signature) => keys && attempt(keys, act, signature);

  return (
    <>
      <section className="step" id="how">
        <h2>How would that work?</h2>
        <p className="lead">
          A login is a short signed message, called a token. The app trusts it because of the signature. Here is a real
          one: press the buttons in order.
        </p>

        <div className="acts" role="group" aria-label="Try it">
          <button type="button" aria-pressed={reached(first, 'honest')} onClick={async () => setFirst(await run('honest', 'old'))}>
            Sign in as Alice
          </button>
          <button type="button" aria-pressed={reached(first, 'forged')} onClick={async () => setFirst(await run('forged', 'old'))}>
            Be Mallory: forge a token
          </button>
          <button type="button" aria-pressed={reached(first, 'quantum')} onClick={async () => setFirst(await run('quantum', 'old'))}>
            Give Mallory a quantum computer
          </button>
        </div>

        {first ? (
          <>
            <Note attempt={first} />
            <p className="explain">{EXPLAIN.old[first.act]}</p>
            {first.act === 'quantum' && (
              <p className="aside">
                One step here is simulated. No quantum computer can do this yet, so we hand Mallory the secret key, which
                is what the quantum computer would compute. The signatures and the app’s check are real.
              </p>
            )}
            <details className="drawer">
              <summary>See the actual token</summary>
              <div className="drawer-body">
                <p>
                  Three parts separated by dots: a header, the message, and the signature. This one is signed with
                  ES256, the elliptic-curve signature most logins use today.
                </p>
                <TokenView token={first.token} />
              </div>
            </details>
          </>
        ) : (
          <p className="explain">Creating keys…</p>
        )}
      </section>

      <section className="step" id="fix">
        <h2>What stops it?</h2>
        <p className="lead">
          A new kind of signature, standardised in 2024 and called ML-DSA. It does the same job with maths that quantum
          computers aren’t known to break.
        </p>

        <div className="acts" role="group" aria-label="Try the fix">
          <button
            type="button"
            aria-pressed={switched && reached(second, 'honest')}
            onClick={async () => {
              setSwitched(true);
              setSecond(await run('honest', 'new'));
            }}
          >
            Switch to the new signature and sign in
          </button>
          <button
            type="button"
            disabled={!switched}
            aria-pressed={reached(second, 'quantum')}
            onClick={async () => setSecond(await run('quantum', 'new'))}
          >
            Give Mallory her quantum computer again
          </button>
        </div>

        {second ? (
          <>
            <Note attempt={second} />
            <p className="explain">{EXPLAIN.new[second.act]}</p>
            <details className="drawer">
              <summary>See the actual token</summary>
              <div className="drawer-body">
                <p>
                  Same three parts. Look at how much of it is signature now: that is the subject of the next section.
                </p>
                <TokenView token={second.token} />
              </div>
            </details>
          </>
        ) : (
          <p className="explain">Nothing has been switched yet. The login above is still using the old signature.</p>
        )}
      </section>
    </>
  );
}
