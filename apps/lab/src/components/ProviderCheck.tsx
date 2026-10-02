import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { analyzeProvider, discoveryUrl } from '@pq-oidc/token-kit/readiness';
import type { CheckStatus, ProviderReport } from '@pq-oidc/token-kit/readiness';
import { PQ_OIDC_SNAPSHOT } from '../data/pq-oidc-snapshot.ts';

const PRESETS = [
  { label: 'Google', issuer: 'https://accounts.google.com' },
  { label: 'Microsoft Entra ID', issuer: 'https://login.microsoftonline.com/common/v2.0' },
  { label: 'Apple', issuer: 'https://appleid.apple.com' },
  { label: 'GitLab', issuer: 'https://gitlab.com' },
  { label: 'Auth0 (demo tenant)', issuer: 'https://samples.auth0.com' },
  { label: 'pq-oidc (this project)', issuer: 'pq-oidc-snapshot' },
];

type Result =
  | { state: 'idle' }
  | { state: 'loading'; issuer: string }
  | { state: 'done'; report: ProviderReport; discovery: unknown; jwks: unknown; snapshot: boolean }
  | { state: 'error'; issuer: string; message: string };

const fmt = new Intl.NumberFormat('en-US');

/**
 * A shared link (?issuer=https://…) re-runs the check for whoever opens it.
 * Only https issuers are honoured from the URL, so a crafted link can't make
 * a visitor's browser probe their own machine.
 */
function issuerFromLink(): string | undefined {
  const value = new URLSearchParams(window.location.search).get('issuer');
  return value?.startsWith('https://') ? value : undefined;
}

function shareLink(issuer: string): string {
  return `${window.location.origin}${window.location.pathname}?issuer=${encodeURIComponent(issuer)}#provider`;
}
const ICON: Record<CheckStatus, string> = { pass: '✓', warn: '!', fail: '✗', info: 'i' };

async function fetchJson(url: string): Promise<{ json: Record<string, unknown>; text: string }> {
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000), credentials: 'omit' });
  if (!response.ok) throw new Error(`${url} answered HTTP ${response.status}`);
  const text = await response.text();
  return { json: JSON.parse(text) as Record<string, unknown>, text };
}

async function check(issuer: string): Promise<Result> {
  if (issuer === 'pq-oidc-snapshot') {
    const jwks = JSON.parse(PQ_OIDC_SNAPSHOT.jwksText) as Record<string, unknown>;
    const report = analyzeProvider(PQ_OIDC_SNAPSHOT.discovery, jwks, PQ_OIDC_SNAPSHOT.jwksText.length);
    return { state: 'done', report, discovery: PQ_OIDC_SNAPSHOT.discovery, jwks, snapshot: true };
  }
  let url: string;
  try {
    url = new URL(discoveryUrl(issuer)).href;
    if (!url.startsWith('https://') && !url.startsWith('http://localhost')) {
      return { state: 'error', issuer, message: 'Use an https:// issuer URL.' };
    }
  } catch {
    return { state: 'error', issuer, message: 'That doesn’t look like a URL. Try https://your-tenant.okta.com' };
  }
  try {
    const discovery = await fetchJson(url);
    if (typeof discovery.json.jwks_uri !== 'string') throw new Error('The discovery document has no jwks_uri.');
    const jwks = await fetchJson(discovery.json.jwks_uri);
    const report = analyzeProvider(discovery.json, jwks.json, jwks.text.length);
    return { state: 'done', report, discovery: discovery.json, jwks: jwks.json, snapshot: false };
  } catch (error) {
    const message =
      error instanceof TypeError
        ? 'Your browser couldn’t read this provider’s public documents. Some providers block requests from other websites (CORS). The command-line version has no such limit.'
        : error instanceof Error
          ? error.message
          : String(error);
    return { state: 'error', issuer, message };
  }
}

function Verdict({ report, snapshot }: { report: ProviderReport; snapshot: boolean }) {
  const algs = report.idTokenAlgs.join(', ') || 'unknown algorithms';
  const strengths = [...new Set(report.keys.filter((k) => k.use !== 'enc').map((k) => k.strength))].join(', ');
  const text = {
    'not-ready': {
      title: 'Not post-quantum ready',
      body: `Signs login tokens with ${algs} (${strengths}). A large quantum computer could recover these private keys from the public ones and forge a login for any user.`,
    },
    partial: {
      title: 'Migrating: post-quantum keys published',
      body: `Publishes ML-DSA keys next to classical ones, so apps can move to post-quantum ID tokens one at a time. Once no app needs the classical keys, retiring them completes the migration.`,
    },
    ready: {
      title: 'Post-quantum ready',
      body: 'Every signing key is ML-DSA. Tokens from this provider can’t be forged with a quantum computer.',
    },
  }[report.verdict];
  return (
    <div className={`verdict-banner ${report.verdict}`}>
      <b>{text.title}</b>
      <p>{text.body}</p>
      {snapshot && (
        <p className="small">
          Snapshot of this project’s provider. Run <code>npm start</code> and check <code>http://localhost:3000</code>{' '}
          to see it live.
        </p>
      )}
    </div>
  );
}

export function ProviderCheck() {
  const [issuer, setIssuer] = useState(PRESETS[0]!.issuer);
  const [result, setResult] = useState<Result>({ state: 'idle' });
  const [copied, setCopied] = useState(false);
  const checkedIssuer = result.state === 'done' && !result.snapshot ? result.report.issuer : undefined;

  async function run(target: string, updateAddressBar = true) {
    setIssuer(target === 'pq-oidc-snapshot' ? 'http://localhost:3000 (snapshot)' : target);
    setResult({ state: 'loading', issuer: target });
    setCopied(false);
    const next = await check(target);
    setResult(next);
    if (updateAddressBar && next.state === 'done' && !next.snapshot && target.startsWith('https://')) {
      window.history.replaceState(null, '', shareLink(target));
    }
  }

  useEffect(() => {
    void run(issuerFromLink() ?? PRESETS[0]!.issuer, false);
  }, []);

  async function copyLink() {
    if (!checkedIssuer) return;
    try {
      await navigator.clipboard.writeText(shareLink(issuer));
      setCopied(true);
    } catch {
      window.history.replaceState(null, '', shareLink(issuer)); // fall back to the address bar
    }
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    void run(issuer.replace(' (snapshot)', ''));
  }

  return (
    <section className="chapter wrap" id="provider">
      <div className="chapter-head">
        <h2>Is your identity provider ready?</h2>
        <p>
          Every OpenID Connect provider publishes its signing keys. This reads them straight from the provider, in
          your browser, and tells you whether the tokens it issues could be forged with a quantum computer. Try your
          company’s: an Okta, Auth0, Entra ID or Keycloak URL works.
        </p>
      </div>

      <div className="panel tool">
        <form className="tool-input" onSubmit={onSubmit}>
          <label htmlFor="issuer">Issuer URL</label>
          <div className="input-row">
            <input
              id="issuer"
              value={issuer}
              onChange={(e) => setIssuer(e.target.value)}
              placeholder="https://your-tenant.okta.com"
              spellCheck={false}
              autoComplete="url"
            />
            <button className="btn" type="submit" disabled={result.state === 'loading'}>
              {result.state === 'loading' ? 'Checking…' : 'Check'}
            </button>
          </div>
          <div className="presets" role="group" aria-label="Examples">
            {PRESETS.map((p) => (
              <button
                key={p.issuer}
                type="button"
                className={`preset ${p.issuer === 'pq-oidc-snapshot' ? 'pq' : ''}`}
                onClick={() => void run(p.issuer)}
              >
                {p.label}
              </button>
            ))}
          </div>
        </form>

        <div aria-live="polite">
          {result.state === 'error' && (
            <div className="verdict-banner error">
              <b>Couldn’t check {result.issuer}</b>
              <p>{result.message}</p>
              <p className="small">
                From a clone of this repo: <code>npm run check -- {result.issuer}</code>
              </p>
            </div>
          )}

          {result.state === 'done' && (
            <div className="report">
              <Verdict report={result.report} snapshot={result.snapshot} />

              <ul className="checks">
                {result.report.checks.map((c) => (
                  <li key={c.id} className={c.status}>
                    <span className="icon" aria-hidden="true">
                      {ICON[c.status]}
                    </span>
                    <div>
                      <b>{c.label}</b>
                      <span>{c.detail}</span>
                    </div>
                  </li>
                ))}
              </ul>

              <div className="table-wrap">
                <table className="data keys">
                  <thead>
                    <tr>
                      <th>Key ID</th>
                      <th>Type</th>
                      <th>Strength</th>
                      <th>Use</th>
                      <th>Quantum computer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.report.keys.map((k, i) => (
                      <tr key={`${k.kid}-${i}`}>
                        <td title={k.kid}>{k.kid ? (k.kid.length > 18 ? `${k.kid.slice(0, 16)}…` : k.kid) : '—'}</td>
                        <td>{k.kty}</td>
                        <td>{k.strength}</td>
                        <td>{k.use ?? 'sig'}</td>
                        <td>
                          {k.quantumSafe ? (
                            <span className="badge pq">can’t forge</span>
                          ) : (
                            <span className="badge bad">can forge</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <p className="small muted">
                Key set today: <b>{fmt.format(result.report.jwksBytes)} B</b>
                {result.report.verdict === 'not-ready' && (
                  <>
                    {' '}
                    · with one ML-DSA-65 key added: <b>~{fmt.format(result.report.jwksBytesWithMlDsa65)} B</b>. Every app
                    that verifies tokens downloads this.
                  </>
                )}
              </p>

              {checkedIssuer && issuer.startsWith('https://') && (
                <div className="presets">
                  <button type="button" className="preset" onClick={copyLink}>
                    {copied ? 'Link copied' : 'Copy a link to this result'}
                  </button>
                  <span className="small muted">Anyone who opens it gets a fresh, live check of the same provider.</span>
                </div>
              )}

              <details>
                <summary>Raw documents</summary>
                <div className="grid-2">
                  <div className="stack">
                    <span className="small muted">Discovery document</span>
                    <pre className="json tall">{JSON.stringify(result.discovery, null, 2)}</pre>
                  </div>
                  <div className="stack">
                    <span className="small muted">Key set (JWKS)</span>
                    <pre className="json tall">{JSON.stringify(result.jwks, null, 2)}</pre>
                  </div>
                </div>
              </details>
            </div>
          )}
          {result.state === 'loading' && <p className="muted small">Fetching the discovery document and keys…</p>}
        </div>
        <p className="small muted">
          Only public documents are read, directly from the provider. Nothing about you or your check is sent anywhere
          else.
        </p>
      </div>
    </section>
  );
}
