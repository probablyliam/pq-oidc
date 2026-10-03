import { useEffect, useMemo, useState } from 'react';
import { DEFAULT_POLICY, parseTarget } from '@pq-oidc/scan-core/policy';
import { ALGORITHMS } from '@pq-oidc/token-kit/algorithms';
import type { SigningAlg } from '@pq-oidc/token-kit/algorithms';
import { analyzeToken, describeSignature, tokenVerdict } from '@pq-oidc/token-kit/analyze';
import type { TokenAnalysis } from '@pq-oidc/token-kit/analyze';
import { SIZE_LIMITS } from '@pq-oidc/token-kit/limits';
import { projectToken } from '@pq-oidc/token-kit/projection';
import { checkSignature } from '@pq-oidc/token-kit/signature';
import type { SignatureCheck } from '@pq-oidc/token-kit/signature';
import { api } from '../api.ts';
import type { Meta } from '../api.ts';
import { Finding } from '../components/Finding.tsx';
import { Legend } from '../components/Report.tsx';
import { ATTACKS } from '../crypto/attacks.ts';
import type { AttackContext } from '../crypto/attacks.ts';
import { encryptJwt } from '../crypto/jwe.ts';
import { generateKey } from '../crypto/jws.ts';
import { href } from '../router.ts';

/**
 * Reads a token in the browser. The token is never sent anywhere (ADR 0010);
 * to check its signature the page fetches the issuer's public keys, after the
 * user says so, and verifies locally.
 */
interface KeySource {
  /** Where the keys came from, in words. */
  label: string;
  jwks: { keys?: unknown[] };
  /** The issuer the key document declares, when it differs from the token's. */
  declaredIssuer?: string;
}

type KeyState = { status: 'idle' } | { status: 'fetching' } | { status: 'blocked'; reason: string } | { status: 'ready'; source: KeySource; check: SignatureCheck };

const fmt = new Intl.NumberFormat('en-US');
const COOKIE = SIZE_LIMITS.find((l) => l.id === 'cookie')!;
const PROJECTED: SigningAlg[] = ['ES256', 'RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

async function fetchJson(url: string): Promise<Record<string, unknown>> {
  // No cookies, no redirects: a key document is a plain public file.
  const response = await fetch(url, { credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return (await response.json()) as Record<string, unknown>;
}

async function fetchKeysDirectly(issuer: string): Promise<KeySource> {
  const base = issuer.replace(/\/$/, '');
  const discovery = await fetchJson(`${base}/.well-known/openid-configuration`);
  if (typeof discovery.jwks_uri !== 'string') throw new Error('no jwks_uri');
  const jwks = await fetchJson(discovery.jwks_uri);
  return { label: discovery.jwks_uri, jwks, declaredIssuer: discovery.issuer === issuer ? undefined : String(discovery.issuer) };
}

/** A fictional issuer and a token it signed or encrypted, plus the classic ways of tampering with one. */
async function buildExample(id: string): Promise<{ token: string; source?: KeySource }> {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: 'https://login.example-corp.com', aud: 'payroll', sub: 'alice', name: 'Alice Nakamura', email: 'alice.nakamura@example-corp.com', iat: now, exp: now + 3600 };
  // Encrypted tokens carry no signature to check: only the recipient's private key opens them.
  if (id === 'encrypted') return { token: await encryptJwt(claims) };
  const providerKey = await generateKey(id === 'pq' ? 'ML-DSA-65' : 'RS256', 'example-key-1');
  const context: AttackContext = { providerKey, issuer: 'https://login.example-corp.com', audience: 'payroll', claims };
  const attack = ATTACKS.find((a) => a.id === (id === 'pq' ? 'honest' : id)) ?? ATTACKS[0]!;
  return { token: await attack.build(context), source: { label: 'the example issuer’s key set (made on this page)', jwks: { keys: [providerKey.publicJwk] } } };
}

const EXAMPLES: { label: string; picks: [id: string, label: string][] }[] = [
  {
    label: 'Try a token',
    picks: [
      ['honest', 'Typical (RS256)'],
      ['pq', 'Post-quantum (ML-DSA-65)'],
      ['encrypted', 'Encrypted (RSA-OAEP-256)'],
    ],
  },
  {
    label: 'Or a tampered one',
    picks: [
      ['edit-claims', 'Edited after signing'],
      ['alg-none', 'Signature removed'],
      ['alg-confusion', 'Algorithm confusion'],
      ['expired', 'Expired'],
    ],
  },
];

function Facts({ analysis }: { analysis: TokenAnalysis }) {
  const signed = analysis.format === 'jws' && analysis.alg && analysis.alg.kind !== 'none' && analysis.alg.kind !== 'unknown';
  const encrypted = analysis.format === 'jwe';
  return (
    <dl className="three-facts">
      <div className={encrypted ? 'no' : 'yes'}>
        <dt>Encoded</dt>
        <dd>{encrypted ? 'Only the header is readable.' : 'Yes. Anyone holding the token can read it; no key is involved.'}</dd>
      </div>
      <div className={signed ? 'yes' : 'no'}>
        <dt>Signed</dt>
        <dd>
          {encrypted
            ? 'Not visible: whatever is inside is encrypted.'
            : signed
              ? analysis.alg!.publicKey
                ? `Yes, with ${analysis.alg!.alg}. A signature makes changes detectable. It hides nothing.`
                : `With ${analysis.alg!.alg}, a keyed hash rather than a signature: whoever can check it can also make one.`
              : 'No. Anyone could have written this token.'}
        </dd>
      </div>
      <div className={encrypted ? 'yes' : 'no'}>
        <dt>Encrypted</dt>
        <dd>{encrypted ? `Yes: ${analysis.jwe!.alg} delivers the key, ${analysis.jwe!.enc} encrypts the content.` : 'No. Nothing in this token is hidden.'}</dd>
      </div>
    </dl>
  );
}

function Anatomy({ token, analysis }: { token: string; analysis: TokenAnalysis }) {
  const [header = '', payload = '', signature = ''] = token.split('.');
  return (
    <div className="anatomy">
      <p className="token-text" aria-label="The token, coloured by part">
        <span className="part-header">{header}</span>.<span className="part-payload">{payload}</span>.<span className="part-signature">{signature}</span>
      </p>
      <div className="anatomy-parts">
        <section className="part-header">
          <h4>Header</h4>
          <pre>{JSON.stringify(analysis.header, null, 2)}</pre>
        </section>
        <section className="part-payload">
          <h4>Payload</h4>
          <pre>{analysis.payload ? JSON.stringify(analysis.payload, null, 2) : '(not a JSON object)'}</pre>
        </section>
        <section className="part-signature">
          <h4>Signature</h4>
          <p>
            {analysis.signatureBytes === undefined ? 'not valid base64url' : `${fmt.format(analysis.signatureBytes)} bytes`}
            {analysis.signatureBytes === 0 && ': empty'}
          </p>
          <p className="fine">Bytes computed from the header, the payload and a private key. They can be checked, not decoded.</p>
        </section>
      </div>
    </div>
  );
}

function Sizes({ token, analysis }: { token: string; analysis: TokenAnalysis }) {
  const rows = useMemo(() => {
    try {
      return PROJECTED.map((alg) => projectToken(token, alg));
    } catch {
      return [];
    }
  }, [token]);
  const pq = rows.find((r) => r.alg === 'ML-DSA-65');
  if (!pq || analysis.format !== 'jws') return null;
  return (
    <section className="sizes">
      <h4>What the signature algorithm does to this token’s size</h4>
      <p>
        {analysis.alg?.quantum === 'no-known-attack'
          ? `This token already carries a post-quantum signature: ${fmt.format(token.length)} bytes, most of them signature. `
          : `Today it is ${fmt.format(token.length)} bytes. Signed with ML-DSA-65 it would be ${fmt.format(pq.totalBytes)} bytes${
              pq.cookieBytes > COOKIE.bytes ? ', which no longer fits in a browser cookie (4,096 bytes). Browsers drop an oversized cookie without an error. ' : ', which still fits in a browser cookie. '
            }`}
        The sizes are exact: only the signature and the algorithm name change, and signature lengths are fixed by the standards.
      </p>
      <div className="scroll-x">
        <table>
          <thead>
            <tr>
              <th>Signed with</th>
              <th>Signature</th>
              <th>Whole token</th>
              <th>In a cookie</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.alg} className={row.alg === analysis.alg?.alg ? 'current' : ''}>
                <td>
                  {row.alg}
                  {ALGORITHMS[row.alg].quantumSafe ? ' (post-quantum)' : ''}
                </td>
                <td>{fmt.format(ALGORITHMS[row.alg].signatureBytes)} B</td>
                <td>{fmt.format(row.totalBytes)} B</td>
                <td className={row.cookieBytes > COOKIE.bytes ? 'bad' : ''}>{row.cookieBytes > COOKIE.bytes ? `too big by ${fmt.format(row.cookieBytes - COOKIE.bytes)} B` : 'fits'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function TokenView({ meta }: { meta: Meta | null }) {
  const [token, setToken] = useState('');
  const [keys, setKeys] = useState<KeyState>({ status: 'idle' });
  const [exampleId, setExampleId] = useState<string>();
  const analysis = useMemo(() => (token.trim() ? analyzeToken(token) : undefined), [token]);

  function replaceToken(next: string) {
    setToken(next);
    setKeys({ status: 'idle' });
    setExampleId(undefined);
  }

  async function applyKeys(source: KeySource, value = token) {
    setKeys({ status: 'ready', source, check: await checkSignature(value, source.jwks) });
  }

  async function loadExample(id: string) {
    const example = await buildExample(id);
    setToken(example.token);
    setKeys({ status: 'idle' });
    setExampleId(id);
    if (example.source) await applyKeys(example.source, example.token);
  }

  // Start with something to look at.
  useEffect(() => void loadExample('honest'), []);

  const issuer = analysis?.issuerUrl;
  const issuerHost = issuer ? new URL(issuer).host : undefined;

  async function fetchDirectly() {
    if (!issuer) return;
    setKeys({ status: 'fetching' });
    try {
      // The same rules the scanner applies: no internal names or addresses, whatever the token says.
      parseTarget(issuer, { allowedPorts: [...DEFAULT_POLICY.allowedPorts], labOrigins: meta?.labOrigins ?? [] });
      await applyKeys(await fetchKeysDirectly(issuer));
    } catch (error) {
      setKeys({ status: 'blocked', reason: error instanceof Error && error.name === 'TargetRejected' ? error.message : 'Your browser was not allowed to read that issuer’s key document. Many issuers do not let web pages fetch it.' });
    }
  }

  async function fetchThroughScanner() {
    if (!issuer) return;
    setKeys({ status: 'fetching' });
    try {
      const done = await api.scan(issuer, 'issuer-keys');
      const result = done.report && 'kind' in done.report ? done.report : undefined;
      if (!result?.jwks) return setKeys({ status: 'blocked', reason: done.error?.message ?? result?.error ?? 'The scanner could not read the issuer’s keys.' });
      await applyKeys({ label: `${result.jwksUri} (fetched by the scanner)`, jwks: result.jwks, declaredIssuer: result.issuerMatches ? undefined : result.declaredIssuer });
    } catch (error) {
      setKeys({ status: 'blocked', reason: error instanceof Error ? error.message : 'The scanner could not read the issuer’s keys.' });
    }
  }

  const check = keys.status === 'ready' ? keys.check : undefined;
  const verdict = analysis ? tokenVerdict(analysis, check) : undefined;
  const signature = analysis?.format === 'jws' ? describeSignature(analysis, check, keys.status === 'ready' ? keys.source.label : undefined) : undefined;
  const findings = analysis ? [...analysis.findings, ...(signature ? [signature] : [])] : [];
  const ORDER = { observation: 0, inference: 1, undetermined: 2 };
  // What is wrong with the token today, before any quantum computer: the bad findings, in plain titles.
  const alsoNoticed = findings.filter((f) => f.tone === 'bad' && f.id !== 'signature.check').map((f) => f.title);

  return (
    <section className="sheet scan scanning">
      <div className="ask titled">
        <h1>Is this token quantum-safe?</h1>
        <p className="sub">Paste a JWT. It is read here in your browser and never sent anywhere.</p>
        <form className="token-input" onSubmit={(event) => event.preventDefault()}>
          <label htmlFor="jwt" className="sr-only">
            Token
          </label>
          <textarea id="jwt" value={token} onChange={(event) => replaceToken(event.target.value.trim())} spellCheck={false} placeholder="eyJhbGciOi…" rows={4} />
          <dl className="picks">
            {EXAMPLES.map((group) => (
              <div key={group.label}>
                <dt>{group.label}</dt>
                <dd>
                  {group.picks.map(([id, label]) => (
                    <button key={id} type="button" className="pick" aria-pressed={exampleId === id} onClick={() => void loadExample(id)}>
                      {label}
                    </button>
                  ))}
                </dd>
              </div>
            ))}
          </dl>
        </form>
      </div>

      {analysis && verdict && (
        <div className="result">
          <article className="report token-report">
            <header className={`verdict verdict-${verdict.status}`}>
              <p className="verdict-host">{exampleId ? 'An example token made on this page' : issuerHost ? `Issued by ${issuerHost}` : 'Pasted token'}</p>
              <h2>{verdict.headline}</h2>
              <p className="verdict-why">{verdict.explanation}</p>
              {analysis.format === 'jws' && keys.status !== 'ready' && (
                <div className="verdict-action">
                  {issuer ? (
                    <>
                      <button type="button" className="primary" disabled={keys.status === 'fetching'} onClick={() => void fetchDirectly()}>
                        {keys.status === 'fetching' ? 'Checking…' : `Check the signature against ${issuerHost}`}
                      </button>
                      <span className="fine">Fetches the issuer’s public keys. The token stays in your browser.</span>
                    </>
                  ) : (
                    <span className="fine">The signature cannot be checked: the token names no https issuer to fetch public keys from.</span>
                  )}
                  {keys.status === 'blocked' && (
                    <p className="notice caution">
                      {keys.reason}
                      {meta && (
                        <>
                          {' '}
                          <button type="button" className="link" onClick={() => void fetchThroughScanner()}>
                            Let the scanner fetch them instead
                          </button>{' '}
                          (sends the issuer’s address to the scan service, not the token).
                        </>
                      )}
                    </p>
                  )}
                </div>
              )}
              {keys.status === 'ready' && keys.source.declaredIssuer !== undefined && (
                <p className="notice caution">The key document declares the issuer “{keys.source.declaredIssuer}”, which is not the “iss” in this token. A verifier should refuse that mismatch.</p>
              )}
            </header>

            <Facts analysis={analysis} />

            {alsoNoticed.length > 0 && (
              <section className="also">
                <h3>Also noticed</h3>
                <ul>
                  {alsoNoticed.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
                <p className="fine">These are problems today, with or without quantum computers.</p>
              </section>
            )}

            <details className="technical">
              <summary>Technical details</summary>
              {analysis.format === 'jws' && <Anatomy token={token} analysis={analysis} />}
              <Legend />
              <ul className="findings">
                {[...findings]
                  .sort((a, b) => ORDER[a.kind] - ORDER[b.kind])
                  .map((finding) => (
                    <Finding key={finding.id} finding={finding} />
                  ))}
              </ul>
              <Sizes token={token} analysis={analysis} />
              <p>
                <a className="learn-link" href={href('lab', analysis.alg?.quantum === 'no-known-attack' ? { token: 'mldsa' } : { token: 'ecdsa' })}>
                  See where a token is signed and checked, in the login lab
                </a>
              </p>
            </details>
          </article>
        </div>
      )}
    </section>
  );
}
