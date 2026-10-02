import { useEffect, useState } from 'react';
import { ATTACKS, naiveVerify } from '../crypto/attacks.ts';
import type { Attack, AttackContext } from '../crypto/attacks.ts';
import { generateKey, parseJwt, verifyJwt } from '../crypto/jws.ts';
import type { LabKey, VerifyResult } from '../crypto/jws.ts';
import { TokenView } from './TokenView.tsx';

const ISSUER = 'https://login.example.com';
const AUDIENCE = 'payroll';
const ALLOWED = ['ML-DSA-65', 'ES256'];

const now = () => Math.floor(Date.now() / 1000);

interface Verdicts {
  naive: VerifyResult;
  careful: VerifyResult;
}

function Verdict({ who, result, honest }: { who: string; result: VerifyResult; honest: boolean }) {
  const accepted = result.ok;
  const cls = accepted ? (honest ? 'accepted legit' : 'accepted fooled') : 'rejected';
  return (
    <div className={`verdict ${cls}`}>
      <span className="who">{who}</span>
      <span className="outcome">
        {accepted ? (honest ? '✓ Accepted' : '✗ Fooled: accepted') : '✓ Rejected'}
      </span>
      {accepted ? (
        <p>
          Signed in as <b>{String(result.payload.name ?? result.payload.sub)}</b>
          {honest ? '.' : '. The attacker is in.'}
        </p>
      ) : (
        <p>
          <code>{result.code}</code>: {result.reason}
        </p>
      )}
    </div>
  );
}

export function AttackPlayground() {
  const [providerKey, setProviderKey] = useState<LabKey>();
  const [attack, setAttack] = useState<Attack>(ATTACKS.find((a) => a.id === 'alg-none')!);
  const [token, setToken] = useState('');
  const [edited, setEdited] = useState(false);
  const [verdicts, setVerdicts] = useState<Verdicts>();

  // The provider's ML-DSA-65 key: generated once, in your browser.
  useEffect(() => {
    generateKey('ML-DSA-65', 'provider-2026-09').then(setProviderKey);
  }, []);

  // Build the forged token whenever the attack changes.
  useEffect(() => {
    if (!providerKey) return;
    const ctx: AttackContext = {
      providerKey,
      issuer: ISSUER,
      audience: AUDIENCE,
      claims: { iss: ISSUER, aud: AUDIENCE, sub: 'alice', name: 'Alice Nakamura', iat: now(), exp: now() + 3600 },
    };
    let cancelled = false;
    attack.build(ctx).then((t) => {
      if (!cancelled) {
        setToken(t);
        setEdited(false);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [attack, providerKey]);

  // Run both verifiers on the current token (including hand edits).
  useEffect(() => {
    if (!providerKey || !token) return;
    let cancelled = false;
    const jwks = [providerKey.publicJwk];
    Promise.all([
      naiveVerify(token, jwks),
      verifyJwt(token, jwks, { issuer: ISSUER, audience: AUDIENCE, algorithms: ALLOWED }),
    ]).then(([naive, careful]) => {
      if (!cancelled) setVerdicts({ naive, careful });
    });
    return () => {
      cancelled = true;
    };
  }, [token, providerKey]);

  const parsed = parseJwt(token);
  const honest = attack.id === 'honest' && !edited;

  return (
    <div className="tool">
      <p>
        A stronger signature is useless if the app checks it badly. Each attack below is built with real cryptography
        and checked twice: by a careless verifier with mistakes real libraries have shipped, and by the one pq-oidc uses.
      </p>
      <div className="attack-layout">
        <div className="attack-list" role="group" aria-label="Attacks">
          {ATTACKS.map((a) => (
            <button key={a.id} type="button" aria-pressed={a.id === attack.id} onClick={() => setAttack(a)}>
              <b>{a.title}</b>
              <span>{a.id === 'honest' ? 'Baseline' : a.defense.split('.')[0]}</span>
            </button>
          ))}
        </div>

        <div className="panel attack-detail">
          <div style={{ display: 'grid', gap: 6 }}>
            <h3>{attack.title}</h3>
            <p>{attack.story}</p>
          </div>

          {verdicts ? (
            <div className="verdicts" aria-live="polite">
              <Verdict who="Naive verifier" result={verdicts.naive} honest={honest} />
              <Verdict who="pq-oidc verifier" result={verdicts.careful} honest={honest} />
            </div>
          ) : (
            <p className="muted small">Generating the provider’s ML-DSA-65 key…</p>
          )}

          <div className="callout info small">
            <b>Why the pq-oidc verifier holds:</b> {attack.defense}
          </div>

          <div style={{ display: 'grid', gap: 8 }}>
            <span className="eyebrow">The token the attacker sends</span>
            {token && <TokenView token={token} />}
          </div>

          {parsed && (
            <div className="grid-2">
              <div className="stack">
                <span className="eyebrow">Header</span>
                <pre className="json">{JSON.stringify(parsed.header, null, 2)}</pre>
              </div>
              <div className="stack">
                <span className="eyebrow">Claims</span>
                <pre className="json">{JSON.stringify(parsed.payload, null, 2)}</pre>
              </div>
            </div>
          )}

          <details>
            <summary>Edit the token yourself</summary>
            <label className="small muted" htmlFor="token-editor">
              Change any character and both verifiers re-check it instantly.
            </label>
            <textarea
              id="token-editor"
              className="token"
              spellCheck={false}
              value={token}
              onChange={(e) => {
                setToken(e.target.value.trim());
                setEdited(true);
              }}
            />
          </details>
          <p className="small muted">
            Trusted key: the provider’s ML-DSA-65 public key (<code>kid: provider-2026-09</code>). Allowed algorithms:{' '}
            <code>{ALLOWED.join(', ')}</code>.
          </p>
        </div>
      </div>
    </div>
  );
}
