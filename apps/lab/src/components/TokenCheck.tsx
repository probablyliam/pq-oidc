import { useEffect, useMemo, useState } from 'react';
import { ALGORITHMS } from '@pq-oidc/token-kit/algorithms';
import type { SigningAlg } from '@pq-oidc/token-kit/algorithms';
import { SIZE_LIMITS } from '@pq-oidc/token-kit/limits';
import { measureJwt } from '@pq-oidc/token-kit/measure';
import { projectToken } from '@pq-oidc/token-kit/projection';
import type { Projection } from '@pq-oidc/token-kit/projection';
import { generateKey, parseJwt, resignJwt, signJwt } from '../crypto/jws.ts';
import { ByteMap } from './ByteMap.tsx';

const ALGS: SigningAlg[] = ['ES256', 'RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
const fmt = new Intl.NumberFormat('en-US');
const COOKIE = SIZE_LIMITS.find((l) => l.id === 'cookie')!;
const NGINX = SIZE_LIMITS.find((l) => l.id === 'nginx-header')!;
const NODE = SIZE_LIMITS.find((l) => l.id === 'node-headers')!;

/** An example enterprise ID token (fictional values, shaped like a real workforce IdP's). */
async function exampleToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const key = await generateKey('RS256', 'Kq2mTz9xL1vB8nR4cWf0hYp3sJ6gA7dE');
  return signJwt(key, {
    aud: '6f1c9d2e-4b7a-4e3c-9a8f-2d5b7c1e0f94',
    iss: 'https://login.example-corp.com/3c8e5a1f-9b2d-4f6e-8a7c-1d4b9e2f6a03/v2.0',
    iat: now,
    nbf: now,
    exp: now + 3600,
    auth_time: now - 42,
    amr: ['pwd', 'mfa'],
    email: 'alice.nakamura@example-corp.com',
    name: 'Alice Nakamura',
    given_name: 'Alice',
    family_name: 'Nakamura',
    oid: '0b7d3e9a-5c2f-4a1e-b8d6-7f3c9e1a4b25',
    preferred_username: 'alice.nakamura@example-corp.com',
    roles: ['Payroll.Read', 'Expenses.Submit'],
    groups: ['b2e8f1c4-3a7d-4e9b-8c2f-5d1a6e9b3c70', 'e4a9c7d2-1f3b-4c8e-9a5d-2b7f0e6c1a38', '7c3f1e9a-8b2d-4a6e-9c5f-3e1b7d4a2c86'],
    sid: '9f2c6e1a-3d8b-4f7e-a5c9-1b4e8d2a6f37',
    sub: 'Xk3pQ9vL2mN8rT5wY1zA7cF4hJ6gB0dS',
    tid: '3c8e5a1f-9b2d-4f6e-8a7c-1d4b9e2f6a03',
    uti: 'pX9kL2mQ7vR4tY8wZ1aB3c',
    ver: '2.0',
  });
}

function Fit({ used, limit }: { used: number; limit: number }) {
  return used <= limit ? (
    <span className="badge good">fits</span>
  ) : (
    <span className="badge bad">too big by {fmt.format(used - limit)} B</span>
  );
}

export function TokenCheck() {
  const [token, setToken] = useState('');
  const [isExample, setIsExample] = useState(true);
  const [proof, setProof] = useState<{ token: string; ms: number; projected: number }>();
  const [proving, setProving] = useState(false);

  useEffect(() => {
    exampleToken().then(setToken);
  }, []);

  const parsed = useMemo(() => (token ? parseJwt(token) : undefined), [token]);
  const measurement = useMemo(() => {
    try {
      return parsed ? measureJwt(token.trim()) : undefined;
    } catch {
      return undefined;
    }
  }, [token, parsed]);
  const projections = useMemo<Projection[]>(
    () => (measurement ? ALGS.map((alg) => projectToken(token.trim(), alg)) : []),
    [token, measurement],
  );
  const pq65 = projections.find((p) => p.alg === 'ML-DSA-65');
  const max = Math.max(NGINX.bytes * 1.04, ...projections.map((p) => p.totalBytes * 1.02));
  const pct = (n: number) => `${(n / max) * 100}%`;

  async function prove() {
    if (!parsed || !pq65) return;
    setProving(true);
    const key = await generateKey('ML-DSA-65');
    const start = performance.now();
    const signed = await resignJwt(key, token);
    setProof({ token: signed, ms: performance.now() - start, projected: pq65.totalBytes });
    setProving(false);
  }

  const claimCount = parsed ? Object.keys(parsed.payload).length : 0;

  return (
    <div className="tool">
      <p className="tool-intro">
        Paste a login token (a JWT) from your own system. It is decoded in your browser and never uploaded. You’ll see
        how big it gets with each quantum-proof signature and which limits it breaks.
      </p>
        <div className="tool-input">
          <label htmlFor="jwt">JWT</label>
          <textarea
            id="jwt"
            className="token"
            spellCheck={false}
            value={token}
            placeholder="eyJhbGciOi…"
            onChange={(e) => {
              setToken(e.target.value.trim());
              setIsExample(false);
              setProof(undefined);
            }}
          />
          <div className="presets">
            <button
              type="button"
              className="preset"
              onClick={() => {
                setIsExample(true);
                setProof(undefined);
                void exampleToken().then(setToken);
              }}
            >
              Use an example token
            </button>
            <span className="small muted">
              {isExample
                ? 'Showing a fictional workforce ID token (RS256).'
                : 'Tip: use an expired or test token. Nothing leaves this page either way.'}
            </span>
          </div>
        </div>

        {token && !measurement && <div className="verdict-banner error">That isn’t a compact JWT (three base64url parts separated by dots).</div>}

        {measurement && pq65 && (
          <div className="token-report">
            <div className={`verdict-banner ${pq65.cookieBytes > COOKIE.bytes ? 'not-ready' : 'partial'}`}>
              <b>
                {measurement.alg} today: {fmt.format(measurement.totalBytes)} bytes. With ML-DSA-65:{' '}
                {fmt.format(pq65.totalBytes)} bytes ({(pq65.totalBytes / measurement.totalBytes).toFixed(1)}×).
              </b>
              <p>
                {pq65.cookieBytes > COOKIE.bytes
                  ? 'It would no longer fit in a browser cookie. If your app keeps this token in a cookie, users would be signed out without any error.'
                  : 'It still fits in a single cookie, but with less than ' +
                    fmt.format(COOKIE.bytes - pq65.cookieBytes) +
                    ' bytes to spare: a few more claims and it won’t.'}{' '}
                {claimCount} claims, {fmt.format(measurement.encodedPayloadBytes)} bytes of them; the rest is signature and header.
              </p>
            </div>

            <div className="size-chart" role="img" aria-label="Projected token size by algorithm against browser and server limits">
              {projections.map((p, i) => (
                <div className="size-row" key={p.alg}>
                  <span className="label">
                    {p.alg}
                    {p.alg === measurement.alg && <small> yours</small>}
                  </span>
                  <div className="size-track">
                    <div className="size-bar" style={{ width: pct(p.totalBytes) }}>
                      <span className="part-header" style={{ width: `${(p.headerBytes / p.totalBytes) * 100}%` }} />
                      <span className="part-payload" style={{ width: `${(p.payloadBytes / p.totalBytes) * 100}%` }} />
                      <span className="part-signature" style={{ width: `${(p.signatureBytes / p.totalBytes) * 100}%` }} />
                    </div>
                    <span className="limit-line" style={{ left: pct(COOKIE.bytes) }} />
                    <span className="limit-line soft" style={{ left: pct(NGINX.bytes) }} />
                    {i === 0 && (
                      <>
                        <span className="limit-label" style={{ left: pct(COOKIE.bytes) }}>
                          cookie 4 KB
                        </span>
                        <span className="limit-label soft" style={{ left: pct(NGINX.bytes) }}>
                          nginx header 8 KB
                        </span>
                      </>
                    )}
                  </div>
                  <span className={`value ${p.cookieBytes > COOKIE.bytes ? 'over' : ''}`}>{fmt.format(p.totalBytes)} B</span>
                </div>
              ))}
            </div>
            <div className="legend">
              <span>
                <i className="part-header" />
                Header
              </span>
              <span>
                <i className="part-payload" />
                Claims
              </span>
              <span>
                <i className="part-signature" />
                Signature
              </span>
            </div>

            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Signed with</th>
                    <th>Token</th>
                    <th title={COOKIE.source}>In a cookie</th>
                    <th title={NGINX.source}>As a Bearer header (nginx)</th>
                    <th title={NODE.source}>Headers left in Node.js</th>
                  </tr>
                </thead>
                <tbody>
                  {projections.map((p) => (
                    <tr key={p.alg}>
                      <td>
                        {p.alg} {ALGORITHMS[p.alg].quantumSafe && <span className="badge pq">PQ</span>}
                      </td>
                      <td>{fmt.format(p.totalBytes)} B</td>
                      <td>
                        <Fit used={p.cookieBytes} limit={COOKIE.bytes} />
                      </td>
                      <td>
                        <Fit used={p.bearerHeaderBytes} limit={NGINX.bytes} />
                      </td>
                      <td>{fmt.format(NODE.bytes - p.bearerHeaderBytes)} B</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="small muted">
              Limits used: {SIZE_LIMITS.map((l) => `${l.label}, ${fmt.format(l.bytes)} B (${l.source})`).join('; ')}.
            </p>

            <div className="proof">
              <div>
                <b>Don’t take the projection on trust.</b>
                <p className="small muted">
                  Sizes above are calculated from the standards. This re-signs your exact header and claims with a
                  fresh ML-DSA-65 key, right here, so you can compare.
                </p>
              </div>
              <button className="btn ghost" type="button" onClick={prove} disabled={proving}>
                {proving ? 'Signing…' : 'Re-sign it with ML-DSA-65'}
              </button>
            </div>
            {proof && (
              <div className="proof-result">
                <p className="small">
                  Signed in {proof.ms.toFixed(1)} ms: <b>{fmt.format(proof.token.length)} bytes</b>, projected{' '}
                  {fmt.format(proof.projected)} bytes{' '}
                  {proof.token.length === proof.projected ? (
                    <span className="badge good">exact match</span>
                  ) : (
                    <span className="badge bad">differs</span>
                  )}
                </p>
                <ByteMap token={proof.token} columns={128} limit={COOKIE.bytes - 9} label="Your token re-signed with ML-DSA-65" />
                <details>
                  <summary>The re-signed token</summary>
                  <pre className="json tall">{proof.token}</pre>
                </details>
              </div>
            )}
          </div>
        )}
      </div>
  );
}
