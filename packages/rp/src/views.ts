import { ALGORITHMS, COOKIE_BYTE_LIMIT, html, renderPage } from '@pq-oidc/token-kit';
import type { JwtMeasurement, RejectionCode, SafeHtml } from '@pq-oidc/token-kit';
import type { RpPreset } from './presets.ts';

const fmt = new Intl.NumberFormat('en-US');

function algBadge(alg: string): SafeHtml {
  const quantumSafe = ALGORITHMS[alg as keyof typeof ALGORITHMS]?.quantumSafe ?? false;
  return html`<span class="badge ${quantumSafe ? 'pq' : 'classical'}">${alg}</span>`;
}

function header(app: RpPreset): SafeHtml {
  return html`<div class="brand"><span class="brand-mark">PQ</span>pq-oidc demo · ${app.appName}</div>`;
}

function acceptedLine(app: RpPreset): SafeHtml {
  return html`<p class="small">Accepts ID tokens signed with ${app.acceptedAlgs.map((a) => html`${algBadge(a)} `)}</p>`;
}

export function signedOutPage(nonce: string, app: RpPreset, providerUrl: string): string {
  return renderPage({
    title: app.appName,
    nonce,
    body: html`${header(app)}
      <section class="card">
        <h1>${app.appName}</h1>
        <p class="muted">${app.tagline}</p>
        ${acceptedLine(app)}
        <div class="row"><a class="button" href="/login">Sign in with pq-oidc</a></div>
      </section>
      <section class="card small">
        <h2>What this demo shows</h2>
        <p>Signing in sends you to the <a href="${providerUrl}/">identity provider</a>. It sends back an ID token: a signed
        statement of who you are. This app checks the signature against the provider's public keys and only accepts
        the algorithms listed above.</p>
      </section>`,
  });
}

export interface CookieExperiment {
  /** Bytes the browser would count for the naive "store the whole token in a cookie" approach. */
  cookieBytes: number;
  /** Did the browser send the naive cookie back on this request? */
  keptByBrowser: boolean;
}

export interface SignedInPageOptions {
  nonce: string;
  app: RpPreset;
  claims: Record<string, unknown>;
  token: string;
  measurement: JwtMeasurement;
  experiment: CookieExperiment;
  otherAppUrl: string | undefined;
}

export function signedInPage(options: SignedInPageOptions): string {
  const { nonce, app, claims, token, measurement: m, experiment } = options;
  const info = ALGORITHMS[m.alg as keyof typeof ALGORITHMS];
  const scaleMax = Math.max(COOKIE_BYTE_LIMIT * 1.25, m.cookieBytes * 1.05);
  const pct = (n: number) => `${((n / scaleMax) * 100).toFixed(2)}%`;
  const tooBig = !m.fitsInCookie;

  return renderPage({
    title: `${app.appName} · signed in`,
    nonce,
    extraCss: `.size-fill { width: ${pct(m.cookieBytes)}; } .size-limit { left: ${pct(COOKIE_BYTE_LIMIT)}; }`,
    body: html`${header(app)}
      <section class="card">
        <div class="row spread">
          <h1>Hi, ${claims.given_name ?? claims.name ?? claims.sub}</h1>
          <form method="post" action="/logout"><button class="secondary" type="submit">Sign out</button></form>
        </div>
        <p class="muted">Signed in as <b>${claims.name}</b> (${claims.email}). ${app.appName} verified your ID token's
        ${algBadge(m.alg)} signature against the provider's public key <code>${m.kid?.slice(0, 12)}…</code></p>
        <div class="stats">
          <div class="stat"><span class="small muted">Signature algorithm</span><b>${m.alg}</b>
            <span class="small">${info?.quantumSafe ? `Post-quantum, NIST category ${info.nistCategory}` : 'Classical, breakable by a quantum computer'}</span></div>
          <div class="stat"><span class="small muted">Whole ID token</span><b>${fmt.format(m.totalBytes)} B</b></div>
          <div class="stat"><span class="small muted">Signature alone</span><b>${fmt.format(m.signatureBytes)} B</b></div>
        </div>
      </section>

      <section class="card">
        <h2>Does the token fit in a cookie?</h2>
        <p class="small muted">Many apps store the ID token in a browser cookie. Browsers drop any cookie over
        ${fmt.format(COOKIE_BYTE_LIMIT)} bytes, silently. On sign-in, this app tried that naive approach.</p>
        <div class="bar" role="img" aria-label="Cookie size ${m.cookieBytes} bytes against a ${COOKIE_BYTE_LIMIT} byte limit">
          <span class="size-fill ${info?.quantumSafe ? '' : 'classical'}"></span>
          <i class="size-limit"></i>
        </div>
        <p class="small mono">${fmt.format(m.cookieBytes)} B of ${fmt.format(COOKIE_BYTE_LIMIT)} B allowed</p>
        ${experiment.keptByBrowser
          ? html`<div class="notice good">Your browser kept the ${fmt.format(experiment.cookieBytes)}-byte cookie.</div>`
          : tooBig
            ? html`<div class="notice bad"><b>Your browser silently dropped the ${fmt.format(experiment.cookieBytes)}-byte cookie.</b>
              An app that relies on it would log you straight back out. ${app.appName} avoids the problem by keeping the
              token on the server and putting only a short session ID in the cookie.</div>`
            : html`<div class="notice info">The browser didn't send the cookie back, even though it is under the limit.
              Your browser may be blocking cookies.</div>`}
      </section>

      <section class="card">
        <h2>Inside the token</h2>
        <details><summary>Header</summary><pre>${JSON.stringify(m.header, null, 2)}</pre></details>
        <details><summary>Claims</summary><pre>${JSON.stringify(m.payload, null, 2)}</pre></details>
        <details><summary>Raw token (${fmt.format(m.totalBytes)} characters)</summary><pre>${token}</pre></details>
      </section>
      ${options.otherAppUrl
        ? html`<footer>Compare with the <a href="${options.otherAppUrl}">other demo app</a>. You won't need to type your
          password again because the provider remembers your session.</footer>`
        : ''}`,
  });
}

const EXPLANATIONS: Partial<Record<RejectionCode, string>> = {
  'alg-not-allowed':
    'This is the failure a careful migration avoids. The provider was switched to a signature algorithm this app ' +
    "doesn't support yet. The fix is to upgrade the app first, then change the algorithm the provider uses for it.",
  'bad-signature': 'The token was altered after the provider signed it, or it was never signed by the provider.',
  'unknown-key': "The token names a key the provider doesn't publish, so it can't be trusted.",
  unsecured: 'Unsigned tokens are never accepted.',
};

export function rejectedPage(nonce: string, app: RpPreset, code: string, reason: string): string {
  const explanation = EXPLANATIONS[code as RejectionCode];
  return renderPage({
    title: `${app.appName} · sign-in rejected`,
    nonce,
    body: html`${header(app)}
      <section class="card">
        <h1>Sign-in rejected</h1>
        <div class="notice bad" role="alert"><b>${reason}</b></div>
        ${explanation ? html`<p>${explanation}</p>` : ''}
        ${acceptedLine(app)}
        <p class="small muted">Rejection code: <code>${code}</code></p>
        <div class="row"><a class="button secondary" href="/">Back</a></div>
      </section>`,
  });
}
