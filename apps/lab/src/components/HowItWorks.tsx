import { useState } from 'react';
import type { ReactNode } from 'react';

type Seal = 'ES256' | 'ML-DSA-65';

const STEPS = [
  {
    title: 'You click “Sign in”',
    detail: 'The app sends your browser to the identity provider.',
    active: ['you', 'app', 'provider'],
    flow: 'you → app → provider',
  },
  {
    title: 'You prove who you are',
    detail: 'You type your password at the provider, never at the app.',
    active: ['you', 'provider'],
    flow: 'you ⇄ provider',
  },
  {
    title: 'The provider signs an ID token',
    detail: 'A statement like “this is Alice”, sealed with the provider’s private key.',
    active: ['provider'],
    flow: 'provider signs',
  },
  {
    title: 'The app checks the seal',
    detail: 'Using the provider’s public key. A valid seal means the token is genuine.',
    active: ['app'],
    flow: 'provider → app',
  },
] as const;

const ACTORS: { id: string; name: string; role: string; icon: ReactNode }[] = [
  {
    id: 'you',
    name: 'You',
    role: 'your browser',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
        <circle cx="12" cy="8" r="4" />
        <path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7" />
      </svg>
    ),
  },
  {
    id: 'app',
    name: 'The app',
    role: 'e.g. Payroll',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
        <rect x="3" y="4" width="18" height="14" rx="2" />
        <path d="M3 8h18M8 21h8" />
      </svg>
    ),
  },
  {
    id: 'provider',
    name: 'Identity provider',
    role: 'pq-oidc',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
        <path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6l-8-3Z" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    ),
  },
];

export function HowItWorks() {
  const [step, setStep] = useState(3);
  const [seal, setSeal] = useState<Seal>('ES256');
  const [quantum, setQuantum] = useState(false);
  const current = STEPS[step] ?? STEPS[0];
  const tokenVisible = step >= 2;
  const forged = quantum && seal === 'ES256';

  return (
    <section className="chapter wrap" id="how">
      <div className="chapter-head">
        <h2>How a login works, and where quantum computers break it</h2>
        <p>
          Think of the ID token as an ID card with a wax seal. The app lets you in only if the seal is genuine. The
          question is whether anyone else can make that seal.
        </p>
      </div>

      <div className="how">
        <ol className="steps">
          {STEPS.map((s, i) => (
            <li key={s.title}>
              <button type="button" aria-current={i === step ? 'step' : undefined} onClick={() => setStep(i)}>
                <span className="n">{i + 1}</span>
                <b>{s.title}</b>
                <span>{s.detail}</span>
              </button>
            </li>
          ))}
        </ol>

        <div className="panel stage">
          <div className="actors">
            {ACTORS.map((a) => (
              <div key={a.id} className={`actor ${(current.active as readonly string[]).includes(a.id) ? 'active' : ''}`}>
                {a.icon}
                <b>{a.name}</b>
                <span>{a.role}</span>
              </div>
            ))}
          </div>
          <div className="flow-line" aria-live="polite">
            Step {step + 1}: {current.flow}
          </div>

          <div className={`id-card ${tokenVisible ? 'visible' : ''}`}>
            {tokenVisible ? (
              <>
                <div className={`seal ${seal === 'ML-DSA-65' ? 'pq' : ''} ${forged && step === 3 ? 'broken' : ''}`}>
                  {seal === 'ES256' ? 'ES256' : 'ML-DSA\n65'}
                </div>
                <div>
                  <b>ID token</b>
                  <p className="small mono muted">
                    {'{ "sub": "alice", "name": "Alice Nakamura", "aud": "payroll" }'}
                  </p>
                  <p className="small">
                    Sealed with {seal === 'ES256' ? 'an elliptic-curve signature (classical)' : 'a lattice-based signature (post-quantum)'}.
                  </p>
                </div>
              </>
            ) : (
              <p className="muted small">The ID token appears at step 3.</p>
            )}
          </div>

          <div className="controls">
            <div className="segmented" role="group" aria-label="Signature type">
              <button type="button" className="classical" aria-pressed={seal === 'ES256'} onClick={() => setSeal('ES256')}>
                ES256 seal
              </button>
              <button type="button" className="pq" aria-pressed={seal === 'ML-DSA-65'} onClick={() => setSeal('ML-DSA-65')}>
                ML-DSA-65 seal
              </button>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                className="danger"
                checked={quantum}
                onChange={(e) => {
                  setQuantum(e.target.checked);
                  setStep(3);
                }}
              />
              A large quantum computer exists
            </label>
          </div>

          {quantum ? (
            forged ? (
              <div className="callout bad" role="status">
                <b>Anyone can now forge Alice’s ID card.</b> Shor’s algorithm recovers the provider’s private key from
                its public key, so an attacker can seal any token they like, and the app will accept it.
              </div>
            ) : (
              <div className="callout good" role="status">
                <b>The seal holds.</b> No known quantum algorithm breaks ML-DSA, whose security rests on hard lattice
                problems. Forged tokens are rejected.
              </div>
            )
          ) : (
            <div className="callout info">
              Flip the switch to see what changes when a cryptographically relevant quantum computer exists.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
