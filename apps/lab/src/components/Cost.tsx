import { useEffect, useState } from 'react';
import { COOKIE_BYTE_LIMIT } from '@pq-oidc/token-kit/algorithms';
import { generateKey, signJwt } from '../crypto/jws.ts';
import { ByteMap } from './ByteMap.tsx';

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
    <section className="block" id="catch">
      <h2>So why hasn’t everyone switched?</h2>
      <p className="sub">
        The quantum-proof signature is about fifty times bigger. Here is one login token signed both ways, just now, in
        your browser. One square is one byte.
      </p>

      {pair ? (
        <figure className="bytes">
          <figcaption>
            Today’s signature: <b>{fmt.format(pair.oldToken.length)} bytes</b>
          </figcaption>
          <ByteMap token={pair.oldToken} columns={columns} label={`Token with the old signature: ${pair.oldToken.length} bytes`} />
          <figcaption>
            Quantum-proof signature: <b>{fmt.format(pair.newToken.length)} bytes</b>
          </figcaption>
          <ByteMap
            token={pair.newToken}
            columns={columns}
            limit={cookieRoom}
            label={`Token with the new signature: ${pair.newToken.length} bytes, ${over} more than a cookie holds`}
          />
          <ul className="key">
            <li className="k-header">Header</li>
            <li className="k-payload">Who you are</li>
            <li className="k-signature">Signature</li>
            <li className="k-over">Doesn’t fit in a cookie</li>
          </ul>
        </figure>
      ) : (
        <p className="explain">Signing…</p>
      )}

      <ol className="reasons">
        <li>
          <b>It doesn’t fit.</b> Many apps keep your login token in a browser cookie, which holds 4,096 bytes. The new
          token is {pair ? fmt.format(over) : '…'} bytes over, and the browser <mark>drops it without telling anyone</mark>.
        </li>
        <li>
          <b>Every app has to change first.</b> An app that hasn’t been updated can’t check the new signature, so it
          turns everyone away.
        </li>
        <li>
          <b>It can’t happen all at once.</b> One login service serves many apps, each run by a different team. They
          have to move over one at a time.
        </li>
      </ol>
    </section>
  );
}
