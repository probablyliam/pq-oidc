import { REPO_URL } from '../config.ts';

export function RunIt() {
  return (
    <section className="chapter wrap" id="run">
      <div className="chapter-head">
        <h2>The real system runs with one command</h2>
        <p>
          Everything above runs in your browser. The repository also contains a working OpenID Connect provider and
          two apps that sign you in for real, one receiving ES256 tokens and one receiving ML-DSA-65 tokens, plus a
          command-line version of the checks.
        </p>
      </div>
      <div className="run">
        <pre className="terminal" aria-label="Commands to run the project">
          <span className="c"># Node.js 24.7 or newer</span>
          {'\n'}
          <span className="p">$ </span>git clone {REPO_URL}.git
          {'\n'}
          <span className="p">$ </span>cd pq-oidc && npm install
          {'\n'}
          <span className="p">$ </span>npm start
          {'\n\n'}
          <span className="c"># Legacy App    http://localhost:3001  (ES256)</span>
          {'\n'}
          <span className="c"># PQ-Ready App  http://localhost:3002  (ML-DSA-65)</span>
          {'\n'}
          <span className="c"># sign in as alice / quantum-safe</span>
          {'\n\n'}
          <span className="c"># the provider check, from a terminal (no CORS limits)</span>
          {'\n'}
          <span className="p">$ </span>npm run check -- https://token.actions.githubusercontent.com
        </pre>
        <div className="panel" style={{ display: 'grid', gap: 14 }}>
          <h3>What’s in the repo</h3>
          <ul className="checklist">
            <li>An OpenID Certified library (node-oidc-provider) configured as an OAuth 2.1-style provider: code flow and PKCE only</li>
            <li>Per-app signing algorithms, with ES256 and ML-DSA-65 keys published side by side</li>
            <li>Automated attack tests: alg none, algorithm confusion, code replay, PKCE bypass, open redirects</li>
            <li>A STRIDE threat model and architecture decision records</li>
            <li>A Python verifier that cross-checks the RFC 9964 implementation against Node.js</li>
            <li>Docker image, Helm chart, and a Kubernetes (kind) test in CI</li>
          </ul>
          <a className="btn" href={REPO_URL}>
            Read the code on GitHub
          </a>
        </div>
      </div>
    </section>
  );
}
