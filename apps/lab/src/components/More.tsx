import { REPO_URL } from '../config.ts';

/** The closing block: how to use the check outside the browser, and what stands behind this page. */
export function More() {
  return (
    <section className="block more" id="more">
      <h2>Use it on your own systems</h2>
      <div className="more-grid">
        <div>
          <h3>From a terminal</h3>
          <p>Works for login services that block browsers, and for ones only reachable inside your network.</p>
          <pre className="cmd">
            {`git clone ${REPO_URL}.git
cd pq-oidc && npm install
npm run check -- https://your-login-service`}
          </pre>
        </div>
        <div>
          <h3>The login service behind this page</h3>
          <p>
            pq-oidc is a working login service that signs with both kinds of signature and moves apps across one at a
            time. <code>npm start</code> runs it with two apps you can sign in to, and <code>npm run prove</code> has
            a separate Python checker confirm every token it issues.
          </p>
          <p>
            <a className="cta" href={REPO_URL}>
              Code and evidence on GitHub
            </a>
          </p>
        </div>
      </div>
    </section>
  );
}
