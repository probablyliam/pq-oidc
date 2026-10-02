import { useEffect, useState } from 'react';
import { COOKIE_BYTE_LIMIT } from '@pq-oidc/token-kit/algorithms';
import { generateKey, signJwt } from '../crypto/jws.ts';
import { ByteMap } from './ByteMap.tsx';
import { TokenCheck } from './TokenCheck.tsx';

const COOKIE_NAME = 'id_token';
const fmt = new Intl.NumberFormat('en-US');

interface Pair {
  oldToken: string;
  newToken: string;
}

/** The same login token for a fictional user, signed with the old and the new signature. */
async function signPair(): Promise<Pair> {
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
  const [oldKey, newKey] = await Promise.all([generateKey('ES256', 'key-2019'), generateKey('ML-DSA-65', 'key-2026')]);
  return { oldToken: await signJwt(oldKey, claims), newToken: await signJwt(newKey, claims) };
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
  return narrow ? 64 : 120;
}

export function Cost() {
  const [pair, setPair] = useState<Pair>();
  const columns = useColumns();

  useEffect(() => {
    signPair().then(setPair);
  }, []);

  const cookieRoom = COOKIE_BYTE_LIMIT - COOKIE_NAME.length - 1;
  const over = pair ? pair.newToken.length - cookieRoom : 0;

  return (
    <section className="step wide" id="cost">
      <h2>Why hasn’t everyone switched?</h2>
      <p className="lead">
        The new signature is about fifty times longer. Below is one login token signed both ways, just now, in your
        browser. Each square is one byte.
      </p>

      {pair ? (
        <figure className="bytes">
          <figcaption>
            Old signature: <b>{fmt.format(pair.oldToken.length)} bytes</b>
          </figcaption>
          <ByteMap token={pair.oldToken} columns={columns} label={`Token with the old signature: ${pair.oldToken.length} bytes`} />
          <figcaption>
            New signature: <b>{fmt.format(pair.newToken.length)} bytes</b>
          </figcaption>
          <ByteMap
            token={pair.newToken}
            columns={columns}
            limit={cookieRoom}
            label={`Token with the new signature: ${pair.newToken.length} bytes, ${over} more than a cookie holds`}
          />
          <ul className="key">
            <li className="k-header">Label</li>
            <li className="k-payload">Who you are</li>
            <li className="k-signature">Signature</li>
            <li className="k-over">Doesn’t fit in a cookie</li>
          </ul>
        </figure>
      ) : (
        <p className="explain">Signing…</p>
      )}

      <p className="explain">
        Many apps keep your login token in a browser cookie, and a cookie holds 4,096 bytes. The new token is{' '}
        {pair ? fmt.format(over) : '…'} bytes too long, so the browser <mark>throws it away without telling anyone</mark>.
        The login looks like it worked, then you’re signed out. Every app also needs updated code before it can read
        the new signature at all.
      </p>

      <details className="drawer">
        <summary>Check one of your own tokens</summary>
        <div className="drawer-body">
          <TokenCheck />
        </div>
      </details>
    </section>
  );
}
