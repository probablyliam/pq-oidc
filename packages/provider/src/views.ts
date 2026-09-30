import { ALGORITHMS, html, renderPage } from '@pq-oidc/token-kit';
import type { SafeHtml } from '@pq-oidc/token-kit';
import { DEMO_ACCOUNTS, DEMO_PASSWORD } from './accounts.ts';
import type { DemoClient } from './clients.ts';

const brand = html`<div class="brand"><span class="brand-mark">PQ</span>pq-oidc · identity provider</div>`;

export function algBadge(alg: string): SafeHtml {
  const info = ALGORITHMS[alg as keyof typeof ALGORITHMS];
  const quantumSafe = info?.quantumSafe ?? false;
  return html`<span class="badge ${quantumSafe ? 'pq' : 'classical'}">${alg} · ${quantumSafe ? 'post-quantum' : 'classical'}</span>`;
}

export function landingPage(nonce: string, issuer: string, clients: DemoClient[]): string {
  const rows = clients.map(
    (c) => html`<tr>
      <td><b>${c.name}</b><br><code>${c.clientId}</code></td>
      <td>${algBadge(c.idTokenAlg)}</td>
      <td><a href="${new URL(c.redirectUri).origin}/">${new URL(c.redirectUri).origin}</a></td>
    </tr>`,
  );
  return renderPage({
    title: 'pq-oidc provider',
    nonce,
    body: html`${brand}
      <section class="card">
        <h1>OpenID Connect provider</h1>
        <p class="muted">This server signs ID tokens with a classical key (ES256) or a post-quantum key (ML-DSA-65, RFC 9964),
        chosen per app. It never shows a login screen on its own: open one of the apps below and sign in from there.</p>
        <div class="row">
          <a class="button secondary" href="${issuer}/.well-known/openid-configuration">Discovery document</a>
          <a class="button secondary" href="${issuer}/jwks">Public keys (JWKS)</a>
        </div>
      </section>
      <section class="card">
        <h2>Registered apps</h2>
        <div class="table-wrap"><table>
          <thead><tr><th>App</th><th>ID token signature</th><th>Open</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
      </section>`,
  });
}

export interface LoginPageOptions {
  nonce: string;
  uid: string;
  client: DemoClient | undefined;
  error?: string;
  username?: string;
}

export function loginPage({ nonce, uid, client, error, username }: LoginPageOptions): string {
  const accounts = DEMO_ACCOUNTS.map((a) => a.id).join(' or ');
  return renderPage({
    title: 'Sign in · pq-oidc',
    nonce,
    body: html`${brand}
      <section class="card">
        <h1>Sign in</h1>
        <p>to continue to <b>${client?.name ?? 'an unknown app'}</b></p>
        ${client
          ? html`<div class="notice info small">After you sign in, this app receives an ID token signed with ${algBadge(client.idTokenAlg)}</div>`
          : ''}
        ${error ? html`<div class="notice bad" role="alert">${error}</div>` : ''}
        <form method="post" action="/interaction/${uid}/login" autocomplete="off">
          <label>Username <input name="username" required autofocus value="${username ?? ''}" autocomplete="username"></label>
          <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
          <div class="row">
            <button type="submit">Sign in</button>
            <a class="button secondary" href="/interaction/${uid}/abort">Cancel</a>
          </div>
        </form>
        <p class="small muted">Demo accounts: <code>${accounts}</code>, password <code>${DEMO_PASSWORD}</code>. These are fictional users.</p>
      </section>`,
  });
}

export function errorPage(nonce: string, error: string, description: string | undefined): string {
  return renderPage({
    title: 'Sign-in error · pq-oidc',
    nonce,
    body: html`${brand}
      <section class="card">
        <h1>Something went wrong</h1>
        <div class="notice bad"><code>${error}</code>${description ? html`: ${description}` : ''}</div>
        <p class="muted small">Go back to the app you came from and try signing in again.</p>
      </section>`,
  });
}
