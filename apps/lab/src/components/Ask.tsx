import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { analyzeProvider, discoveryUrl } from '@pq-oidc/token-kit/readiness';
import type { KeySummary, ProviderReport } from '@pq-oidc/token-kit/readiness';
import { PQ_OIDC_SNAPSHOT } from '../data/pq-oidc-snapshot.ts';

/**
 * The page's opening question, answered for a real login service by reading
 * the public keys it signs logins with.
 */
const DEMO = 'pq-oidc-demo';
const SERVICES = [
  { name: 'Google', issuer: 'https://accounts.google.com' },
  { name: 'Microsoft', issuer: 'https://login.microsoftonline.com/common/v2.0' },
  { name: 'Apple', issuer: 'https://appleid.apple.com' },
  { name: 'GitLab', issuer: 'https://gitlab.com' },
  { name: 'A service that has started switching', issuer: DEMO },
];

type Result =
  | { state: 'loading'; name: string }
  | { state: 'done'; name: string; issuer: string; report: ProviderReport; discovery: unknown; jwks: unknown }
  | { state: 'error'; name: string; issuer: string; message: string };

async function fetchJson(url: string): Promise<{ json: Record<string, unknown>; text: string }> {
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000), credentials: 'omit' });
  if (!response.ok) throw new Error(`It answered with an error (HTTP ${response.status}).`);
  const text = await response.text();
  return { json: JSON.parse(text) as Record<string, unknown>, text };
}

async function ask(name: string, issuer: string): Promise<Result> {
  if (issuer === DEMO) {
    const jwks = JSON.parse(PQ_OIDC_SNAPSHOT.jwksText) as Record<string, unknown>;
    const report = analyzeProvider(PQ_OIDC_SNAPSHOT.discovery, jwks, PQ_OIDC_SNAPSHOT.jwksText.length);
    return { state: 'done', name, issuer, report, discovery: PQ_OIDC_SNAPSHOT.discovery, jwks };
  }
  try {
    const discovery = await fetchJson(new URL(discoveryUrl(issuer)).href);
    if (typeof discovery.json.jwks_uri !== 'string') throw new Error('It doesn’t say where its keys are.');
    const jwks = await fetchJson(discovery.json.jwks_uri);
    const report = analyzeProvider(discovery.json, jwks.json, jwks.text.length);
    return { state: 'done', name, issuer, report, discovery: discovery.json, jwks: jwks.json };
  } catch (error) {
    const message =
      error instanceof TypeError
        ? 'Your browser wasn’t allowed to read this service’s keys. Some services block other websites from asking.'
        : error instanceof SyntaxError
          ? 'That address doesn’t look like a login service.'
          : error instanceof Error
            ? error.message
            : String(error);
    return { state: 'error', name, issuer, message };
  }
}

/** A shared link (?issuer=https://…) asks the same question for whoever opens it. Only https is honoured. */
function issuerFromLink(): string | undefined {
  const value = new URLSearchParams(window.location.search).get('issuer');
  return value?.startsWith('https://') ? value : undefined;
}

const hostOf = (issuer: string) => {
  try {
    return new URL(issuer).hostname;
  } catch {
    return issuer;
  }
};

function keyKinds(keys: KeySummary[]): string {
  const signing = keys.filter((k) => k.use !== 'enc' && !k.quantumSafe);
  const kinds = [...new Set(signing.map((k) => (k.kty === 'RSA' ? 'RSA' : k.kty === 'EC' ? 'elliptic-curve' : k.kty)))];
  return kinds.join(' and ') || 'older';
}

function plainKey(k: KeySummary): string {
  if (k.quantumSafe) return `${k.strength} key: no known way to break it, even with a quantum computer`;
  if (k.kty === 'RSA' || k.kty === 'EC' || k.kty === 'OKP') return `${k.strength} key: a quantum computer could work out its secret half`;
  return `${k.strength} key`;
}

function Answer({ result }: { result: Result }) {
  if (result.state === 'loading') {
    return (
      <div className="answer">
        <p className="answer-word pending">…</p>
        <p className="answer-why">Reading {result.name}’s public keys.</p>
      </div>
    );
  }
  if (result.state === 'error') {
    return (
      <div className="answer">
        <p className="answer-word pending">Can’t tell.</p>
        <p className="answer-why">{result.message}</p>
        <p className="answer-note">
          From a copy of this project, the same check runs without that limit: <code>npm run check -- {result.issuer}</code>
        </p>
      </div>
    );
  }
  const { report, name } = result;
  if (report.verdict === 'not-ready') {
    return (
      <div className="answer">
        <p className="answer-word yes">Yes.</p>
        <p className="answer-why">
          {name} signs your logins with {keyKinds(report.keys)} keys. A large enough quantum computer could work out
          the secret half of those keys, then <mark>sign in as anyone</mark>.
        </p>
        <p className="answer-note">
          No quantum computer is big enough yet. Replacing the keys everywhere takes years, which is why it matters
          now.
        </p>
      </div>
    );
  }
  if (report.verdict === 'partial') {
    return (
      <div className="answer">
        <p className="answer-word partly">Partly.</p>
        <p className="answer-why">
          This login service has added a new kind of key that <mark>quantum computers can’t break</mark>, and still
          keeps an old one so apps can move over one at a time. Until the old key is retired, a login could still be
          forged with it.
        </p>
        <p className="answer-note">
          This is this project’s own login service, halfway through the switch. The rest of the page shows what that
          switch involves.
        </p>
      </div>
    );
  }
  return (
    <div className="answer">
      <p className="answer-word no">No.</p>
      <p className="answer-why">
        Every key {name} signs logins with is the new kind. There is no known way to forge them, even with a quantum
        computer.
      </p>
    </div>
  );
}

export function Ask() {
  const [result, setResult] = useState<Result>({ state: 'loading', name: 'Google' });
  const [custom, setCustom] = useState('');
  const [showCustom, setShowCustom] = useState(false);
  const [copied, setCopied] = useState(false);
  const selected = result.state === 'loading' ? undefined : result.issuer;

  async function run(name: string, issuer: string, updateAddressBar = true) {
    setResult({ state: 'loading', name });
    setCopied(false);
    const next = await ask(name, issuer);
    setResult(next);
    if (updateAddressBar && next.state === 'done' && issuer.startsWith('https://')) {
      window.history.replaceState(null, '', `${window.location.pathname}?issuer=${encodeURIComponent(issuer)}`);
    }
  }

  useEffect(() => {
    const linked = issuerFromLink();
    const preset = SERVICES.find((s) => s.issuer === linked);
    if (linked && !preset) {
      setCustom(linked);
      setShowCustom(true);
    }
    void run(preset?.name ?? (linked ? hostOf(linked) : 'Google'), linked ?? SERVICES[0]!.issuer, false);
  }, []);

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    const issuer = custom.trim();
    if (!issuer) return;
    void run(hostOf(issuer), issuer.startsWith('http') ? issuer : `https://${issuer}`);
  }

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
    } catch {
      /* the link is already in the address bar */
    }
  }

  return (
    <section className="step ask" id="ask">
      <h1>Could a quantum computer log in as you?</h1>
      <p className="lead">
        When you sign in with Google or a work account, a login service vouches for you with a digital signature. Pick
        yours to see whether that signature would survive a quantum computer.
      </p>

      <div className="choices" role="group" aria-label="Login service">
        {SERVICES.map((s) => (
          <button key={s.issuer} type="button" aria-pressed={selected === s.issuer} onClick={() => void run(s.name, s.issuer)}>
            {s.name}
          </button>
        ))}
        <button type="button" aria-pressed={showCustom} onClick={() => setShowCustom((v) => !v)}>
          Your company’s…
        </button>
      </div>

      {showCustom && (
        <form className="custom" onSubmit={onSubmit}>
          <label htmlFor="issuer">Your login service’s address</label>
          <div className="field-row">
            <input
              id="issuer"
              value={custom}
              onChange={(e) => setCustom(e.target.value)}
              placeholder="https://your-company.okta.com"
              spellCheck={false}
              autoComplete="url"
            />
            <button type="submit">Check</button>
          </div>
          <p className="hint">
            Works with Okta, Auth0, Microsoft Entra ID, Keycloak and anything else that speaks OpenID Connect. Your
            browser reads the service’s public keys directly; nothing is sent to this site.
          </p>
        </form>
      )}

      <div aria-live="polite">
        <Answer result={result} />
      </div>

      {result.state === 'done' && (
        <details className="drawer">
          <summary>See the evidence</summary>
          <div className="drawer-body">
            <p>
              These are the keys {result.name} publishes right now at <code>{hostOf(String(result.report.issuer))}</code>.
              Anyone can read them; that is how apps check a login.
            </p>
            <ul className="evidence">
              {result.report.keys
                .filter((k) => k.use !== 'enc')
                .map((k, i) => (
                  <li key={`${k.kid}-${i}`} className={k.quantumSafe ? 'safe' : 'weak'}>
                    {plainKey(k)}
                  </li>
                ))}
            </ul>

            <h3>For engineers</h3>
            <ul className="facts">
              {result.report.checks.map((c) => (
                <li key={c.id} className={c.status}>
                  <b>{c.label}.</b> {c.detail}
                </li>
              ))}
              <li>
                <b>Key set size.</b> {result.report.jwksBytes.toLocaleString('en-US')} bytes today
                {result.report.verdict === 'not-ready' &&
                  `, about ${result.report.jwksBytesWithMlDsa65.toLocaleString('en-US')} bytes once one ML-DSA-65 key is added`}
                .
              </li>
            </ul>
            <details className="drawer nested">
              <summary>Raw discovery document and key set</summary>
              <pre className="raw">{JSON.stringify(result.discovery, null, 2)}</pre>
              <pre className="raw">{JSON.stringify(result.jwks, null, 2)}</pre>
            </details>
            {result.issuer.startsWith('https://') && (
              <p>
                <button type="button" className="text-button" onClick={copyLink}>
                  {copied ? 'Link copied' : 'Copy a link to this answer'}
                </button>{' '}
                Whoever opens it gets a fresh check.
              </p>
            )}
          </div>
        </details>
      )}
    </section>
  );
}
