import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { analyzeProvider, discoveryUrl } from '@pq-oidc/token-kit/readiness';
import type { KeySummary, ProviderReport } from '@pq-oidc/token-kit/readiness';
import type { Mode } from '../lab/crypto.ts';
import { TokenCheck } from './TokenCheck.tsx';

/**
 * The tool: type a login service's address, get a readiness report with the
 * evidence it is based on. Examples fill the same input, so there is only ever
 * one thing being checked.
 */
const base = new URL(import.meta.env.BASE_URL, window.location.origin).href.replace(/\/$/, '');
const EXAMPLES = [
  { label: 'Google', issuer: 'https://accounts.google.com' },
  { label: 'Microsoft', issuer: 'https://login.microsoftonline.com/common/v2.0' },
  { label: 'Apple', issuer: 'https://appleid.apple.com' },
  { label: 'GitLab', issuer: 'https://gitlab.com' },
  { label: 'Atlassian', issuer: 'https://auth.atlassian.com' },
  { label: 'Demo: halfway through switching', issuer: `${base}/demo-switching` },
  { label: 'Demo: fully switched', issuer: `${base}/demo-switched` },
];
const isDemo = (issuer: string) => issuer.startsWith(`${base}/demo-`);

interface Done {
  state: 'done';
  issuer: string;
  report: ProviderReport;
  discoveryUrl: string;
  jwksUrl: string;
  discovery: unknown;
  jwks: unknown;
  checkedAt: Date;
}
type Result = { state: 'loading'; issuer: string } | Done | { state: 'error'; issuer: string; message: string };

async function fetchJson(url: string): Promise<{ json: Record<string, unknown>; text: string }> {
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000), credentials: 'omit' });
  if (!response.ok) throw new Error(`The service answered with an error (HTTP ${response.status}).`);
  const text = await response.text();
  return { json: JSON.parse(text) as Record<string, unknown>, text };
}

async function check(input: string): Promise<Result> {
  const issuer = /^https?:\/\//.test(input) ? input : `https://${input}`;
  try {
    const docUrl = new URL(discoveryUrl(issuer)).href;
    const discovery = await fetchJson(docUrl);
    if (typeof discovery.json.jwks_uri !== 'string') throw new Error('The service doesn’t say where its keys are.');
    // The demo services are static files; read their keys from wherever this copy of the site is served.
    const jwksUrl = isDemo(issuer) ? `${issuer}/jwks.json` : discovery.json.jwks_uri;
    const jwks = await fetchJson(jwksUrl);
    return {
      state: 'done',
      issuer,
      report: analyzeProvider(discovery.json, jwks.json, jwks.text.length),
      discoveryUrl: docUrl,
      jwksUrl,
      discovery: discovery.json,
      jwks: jwks.json,
      checkedAt: new Date(),
    };
  } catch (error) {
    const message =
      error instanceof SyntaxError
        ? 'That address didn’t return login-service information. It needs to be the address of an OpenID Connect login service.'
        : error instanceof TypeError
          ? 'Your browser wasn’t allowed to read this service’s keys. Some services (Okta and Slack, for example) block other websites from asking.'
          : error instanceof Error
            ? error.message
            : String(error);
    return { state: 'error', issuer, message };
  }
}

/** A shared link (?issuer=https://…) runs the same check for whoever opens it. Only https is honoured. */
function issuerFromLink(): string | undefined {
  const value = new URLSearchParams(window.location.search).get('issuer');
  return value?.startsWith('https://') ? value : undefined;
}

const host = (url: string) => {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
};

const VERDICT = {
  'not-ready': {
    tone: 'bad',
    title: 'Not quantum-ready',
    text: (r: ProviderReport) =>
      `Logins from this service could be forged by a large quantum computer. It signs them with ${[...new Set(r.keys.filter((k) => k.use !== 'enc').map((k) => k.strength))].join(' and ')} keys.`,
  },
  partial: {
    tone: 'mid',
    title: 'Partly quantum-ready',
    text: () =>
      'This service has added a quantum-proof key and still keeps an old one, so apps can move over one at a time. Logins signed with the old key could still be forged.',
  },
  ready: {
    tone: 'good',
    title: 'Quantum-ready',
    text: () => 'Every key this service signs logins with is quantum-proof. There is no known way to forge them.',
  },
} as const;

function KeyRow({ k }: { k: KeySummary }) {
  return (
    <tr>
      <td>
        <code title={k.kid}>{k.kid ? (k.kid.length > 14 ? `${k.kid.slice(0, 12)}…` : k.kid) : 'unnamed'}</code>
      </td>
      <td>{k.strength}</td>
      <td className={k.quantumSafe ? 'good' : 'bad'}>{k.quantumSafe ? 'Quantum-proof' : 'Breakable by a quantum computer'}</td>
    </tr>
  );
}

function Report({ result, onSeeInLab }: { result: Done; onSeeInLab: (mode: Mode) => void }) {
  const [copied, setCopied] = useState(false);
  const { report } = result;
  const verdict = VERDICT[report.verdict];
  const signingKeys = report.keys.filter((k) => k.use !== 'enc');
  const kinds = [...new Set(signingKeys.map((k) => k.strength))].join(' and ');
  const weak = report.verdict !== 'ready';

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
    } catch {
      /* the link is already in the address bar */
    }
  }

  return (
    <article className={`report ${verdict.tone}`}>
      <header>
        <p className="report-host">{host(report.issuer)}</p>
        <p className="report-verdict">{verdict.title}</p>
        <p>{verdict.text(report)}</p>
        {isDemo(result.issuer) && (
          <p className="fine">
            A demonstration service published by this project so you can see this result. Its keys are real; it has no
            accounts.
          </p>
        )}
      </header>

      <section>
        <h3>The keys it signs logins with</h3>
        <div className="scroll-x">
          <table className="keys">
            <thead>
              <tr>
                <th>Key</th>
                <th>Type</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {signingKeys.map((k, i) => (
                <KeyRow key={`${k.kid}-${i}`} k={k} />
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h3>What this check can and can’t see</h3>
        <dl className="evidence">
          <div>
            <dt>Observed</dt>
            <dd>
              The public keys this service signs login tokens with, read at{' '}
              {result.checkedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} from its own{' '}
              <a href={result.discoveryUrl}>settings</a> and <a href={result.jwksUrl}>keys</a> documents.
            </dd>
          </div>
          <div>
            <dt>Inferred</dt>
            <dd>
              {weak
                ? 'That a large quantum computer could work out the private key behind each breakable public key, and then sign logins as this service.'
                : 'That no known quantum attack recovers the private keys behind these public keys.'}
            </dd>
          </div>
          <div>
            <dt>Not visible from here</dt>
            <dd>
              How the HTTPS connection to this service agrees its keys. That is a separate layer, and a web page can’t
              inspect it. A quantum-safe connection does not make these signatures quantum-safe, or the reverse.
            </dd>
          </div>
        </dl>
        <p>
          <button type="button" className="link" onClick={() => onSeeInLab(weak ? 'classical' : 'pq')}>
            See what {weak ? `a quantum-breakable signature (${kinds})` : 'a quantum-safe signature'} does in a login
          </button>
        </p>
      </section>

      <footer>
        <div className="report-actions">
          {result.issuer.startsWith('https://') && (
            <button type="button" onClick={copyLink}>
              {copied ? 'Link copied' : 'Copy link to this report'}
            </button>
          )}
          <details>
            <summary>Technical details</summary>
            <ul className="findings">
              {report.checks.map((c) => (
                <li key={c.id} className={c.status}>
                  <b>{c.label}.</b> {c.detail}
                </li>
              ))}
              <li>
                <b>Key set size.</b> {report.jwksBytes.toLocaleString('en-US')} bytes
                {report.verdict === 'not-ready' &&
                  `; about ${report.jwksBytesWithMlDsa65.toLocaleString('en-US')} bytes once one ML-DSA-65 key is added`}
                .
              </li>
            </ul>
            <pre>{JSON.stringify(result.discovery, null, 2)}</pre>
            <pre>{JSON.stringify(result.jwks, null, 2)}</pre>
          </details>
        </div>
      </footer>
    </article>
  );
}

export function Checker({ onSeeInLab }: { onSeeInLab: (mode: Mode) => void }) {
  const [mode, setMode] = useState<'service' | 'token'>('service');
  const [input, setInput] = useState(EXAMPLES[0]!.issuer);
  const [result, setResult] = useState<Result>({ state: 'loading', issuer: EXAMPLES[0]!.issuer });

  async function run(issuer: string, updateAddressBar = true) {
    setInput(issuer);
    setResult({ state: 'loading', issuer });
    const next = await check(issuer.trim());
    setResult(next);
    if (updateAddressBar && next.state === 'done' && next.issuer.startsWith('https://')) {
      window.history.replaceState(null, '', `${window.location.pathname}?issuer=${encodeURIComponent(next.issuer)}`);
    }
  }

  useEffect(() => {
    void run(issuerFromLink() ?? EXAMPLES[0]!.issuer, false);
  }, []);

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (input.trim()) void run(input);
  }

  return (
    <section className="tool-top" id="check">
      <h1>Is your login quantum-ready?</h1>
      <p className="sub">
        Check whether a quantum computer could forge sign-ins from Google, your company’s login service, or any other.
      </p>

      <div className="tool-panel">
        <div className="tabs" role="tablist">
          <button type="button" role="tab" aria-selected={mode === 'service'} onClick={() => setMode('service')}>
            Check a login service
          </button>
          <button type="button" role="tab" aria-selected={mode === 'token'} onClick={() => setMode('token')}>
            Check a login token
          </button>
        </div>

        {mode === 'service' ? (
          <>
            <form className="scan" onSubmit={onSubmit}>
              <label htmlFor="issuer">Login service address</label>
              <div className="scan-row">
                <input
                  id="issuer"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="https://your-company.okta.com"
                  spellCheck={false}
                  autoComplete="url"
                />
                <button type="submit" className="primary" disabled={result.state === 'loading'}>
                  {result.state === 'loading' ? 'Checking…' : 'Check'}
                </button>
              </div>
              <p className="examples">
                Try:{' '}
                {EXAMPLES.map((e) => (
                  <button key={e.issuer} type="button" className="link" onClick={() => void run(e.issuer)}>
                    {e.label}
                  </button>
                ))}
              </p>
            </form>

            <div aria-live="polite">
              {result.state === 'loading' && <p className="scan-status">Reading {host(result.issuer)}’s public keys…</p>}
              {result.state === 'error' && (
                <article className="report mid">
                  <header>
                    <p className="report-host">{host(result.issuer)}</p>
                    <p className="report-verdict">Couldn’t check</p>
                    <p>{result.message}</p>
                    <p>
                      The command-line version has no such limit: <code>npm run check -- {result.issuer}</code>
                    </p>
                  </header>
                </article>
              )}
              {result.state === 'done' && <Report result={result} onSeeInLab={onSeeInLab} />}
            </div>
          </>
        ) : (
          <TokenCheck onSeeInLab={onSeeInLab} />
        )}
      </div>
    </section>
  );
}
