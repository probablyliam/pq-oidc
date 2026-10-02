import { REPO_URL } from '../config.ts';
import { AttackPlayground } from './AttackPlayground.tsx';

const OIDF_POST = 'https://openid.net/post-quantum-openid-connect/';

export function Real() {
  return (
    <section className="step wide" id="real">
      <h2>Is any of this real?</h2>
      <p className="lead">
        Yes. Behind this page is pq-oidc, a working login service that signs with both kinds of signature and moves apps
        across one at a time. The checks you just used are the same code.
      </p>

      <div className="columns">
        <div>
          <h3>What it is</h3>
          <ul className="plain">
            <li>A login service built on certified open-source software, holding the old key and the new key side by side.</li>
            <li>Two example apps you can sign in to: one still on the old signature, one on the new.</li>
            <li>The check from the top of this page, as a command you can point at any login service.</li>
          </ul>
          <pre className="cmd">
            {`git clone ${REPO_URL}.git
cd pq-oidc
npm install
npm start
npm run check -- https://your-login-service`}
          </pre>
          <p>
            <a className="cta" href={REPO_URL}>
              Read the code on GitHub
            </a>
          </p>
        </div>

        <div>
          <h3>How you know it works</h3>
          <p>
            One command starts the service, signs in for real, and has a second checker, written separately in Python,
            confirm every token. It runs on every change.
          </p>
          <pre className="cmd log">
            {`$ npm run prove
1. Real sign-ins against the login service
   old-signature token: 498 bytes
   new-signature token: 4,824 bytes
2. Checked independently in Python
   ✓ accepts the new token
   ✓ an old-only app refuses it
   ✓ a tampered token is rejected
3. Same verdicts as the raw keys
   ✓ this service: partly switched
   ✓ Google: not switched
All claims held.`}
          </pre>
        </div>
      </div>

      <h3>Has this been done before?</h3>
      <p className="explain">
        The size problem is known: the <a href={OIDF_POST}>OpenID Foundation described it</a> in September 2026. What
        this project adds is a way to check any login service yourself, exact numbers for your own tokens, and a
        working switch you can run and break.
      </p>

      <details className="drawer">
        <summary>More ways to forge a token, for engineers</summary>
        <div className="drawer-body">
          <AttackPlayground />
        </div>
      </details>
    </section>
  );
}
