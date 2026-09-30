import { useEffect, useState } from 'react';
import { COOKIE_BYTE_LIMIT } from '@pq-oidc/token-kit/algorithms';
import { generateKey, signJwt } from '../crypto/jws.ts';
import { REPO_URL } from '../config.ts';
import { ByteMap } from './ByteMap.tsx';

const COOKIE_NAME = 'id_token';
const fmt = new Intl.NumberFormat('en-US');

interface Specimen {
  classical: string;
  pq: string;
}

/** The same ID token for a fictional user, signed two ways. */
async function signSpecimens(): Promise<Specimen> {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: 'https://login.example.com',
    aud: 'payroll',
    sub: 'alice',
    name: 'Alice Nakamura',
    given_name: 'Alice',
    family_name: 'Nakamura',
    email: 'alice.nakamura@example.com',
    email_verified: true,
    nonce: 'n-0S6_WzA2Mj',
    auth_time: now,
    iat: now,
    exp: now + 3600,
  };
  const [ec, pq] = await Promise.all([generateKey('ES256', 'ec-2026-09'), generateKey('ML-DSA-65', 'pq-2026-09')]);
  return { classical: await signJwt(ec, claims), pq: await signJwt(pq, claims) };
}

function useColumns(): number {
  const query = '(max-width: 640px)';
  const [narrow, setNarrow] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const media = window.matchMedia(query);
    const update = () => setNarrow(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);
  return narrow ? 64 : 128;
}

export function Hero() {
  const [specimen, setSpecimen] = useState<Specimen>();
  const [showText, setShowText] = useState(false);
  const columns = useColumns();

  useEffect(() => {
    signSpecimens().then(setSpecimen);
  }, []);

  const cookieLimit = COOKIE_BYTE_LIMIT - COOKIE_NAME.length - 1;
  const overBy = specimen ? specimen.pq.length - cookieLimit : 0;

  return (
    <section className="hero">
      <div className="wrap hero-grid">
        <div className="hero-copy">
          <h1>Login tokens are getting quantum-safe signatures. They’re also getting nine times bigger.</h1>
          <p className="lede">
            When you sign in with a work or Google account, the app receives a signed <b>ID token</b> that says who you
            are. A large quantum computer could forge today’s signatures. <b>pq-oidc</b> is a working identity provider
            that moves apps to ML-DSA, the new post-quantum signature standard, one app at a time, and this page shows
            what that changes.
          </p>
          <div className="actions">
            <a className="btn" href="#provider">
              Check your identity provider
            </a>
            <a className="btn ghost" href="#token">
              Check a token
            </a>
            <a className="btn ghost" href={REPO_URL}>
              Source code
            </a>
          </div>
        </div>

        <figure className="specimen">
          <figcaption>
            <b>The same login token for Alice, signed two ways</b>
            <span>Signed in your browser a moment ago. Each square is one byte.</span>
          </figcaption>
          {specimen ? (
            <>
              <div className="specimen-row">
                <div className="specimen-label">
                  <span className="badge classical">ES256 · today</span>
                  <b>{fmt.format(specimen.classical.length)} bytes</b>
                </div>
                <ByteMap token={specimen.classical} columns={columns} label={`ES256 token: ${specimen.classical.length} bytes`} />
              </div>
              <div className="specimen-row">
                <div className="specimen-label">
                  <span className="badge pq">ML-DSA-65 · post-quantum</span>
                  <b>{fmt.format(specimen.pq.length)} bytes</b>
                </div>
                <ByteMap
                  token={specimen.pq}
                  columns={columns}
                  limit={cookieLimit}
                  label={`ML-DSA-65 token: ${specimen.pq.length} bytes, ${overBy} bytes over the cookie limit`}
                />
              </div>
              <div className="legend">
                <span>
                  <i className="part-header" />
                  Header
                </span>
                <span>
                  <i className="part-payload" />
                  Who you are (claims)
                </span>
                <span>
                  <i className="part-signature" />
                  Signature
                </span>
                <span>
                  <i className="part-over" />
                  Past the 4,096-byte cookie limit: {fmt.format(overBy)} bytes a browser silently drops
                </span>
              </div>
              <button type="button" className="link-button" onClick={() => setShowText((s) => !s)}>
                {showText ? 'Hide the token text' : 'Show the token text'}
              </button>
              {showText && (
                <div className="specimen-text">
                  <code>{specimen.classical}</code>
                  <code>{specimen.pq}</code>
                </div>
              )}
            </>
          ) : (
            <p className="muted small">Signing…</p>
          )}
        </figure>
      </div>
    </section>
  );
}
