import { useEffect, useState } from 'react';
import { api } from './api.ts';
import type { Meta, SessionInfo } from './api.ts';
import { href, useRoute } from './router.ts';
import { CompareView, HistoryView } from './views/HistoryView.tsx';
import { LearnView } from './views/LearnView.tsx';
import { MigrateView } from './views/MigrateView.tsx';
import { ScanView } from './views/ScanView.tsx';
import { TokenView } from './views/TokenView.tsx';

const REPO_URL = 'https://github.com/probablyliam/pq-oidc';

const SIGN_IN_ERRORS: Record<string, string> = {
  expired: 'That sign-in attempt expired or was already used. Try again.',
  cancelled: 'Sign-in was cancelled.',
  refused: 'The identity provider refused the sign-in.',
  'token-rejected': 'The identity provider’s token did not pass verification, so you were not signed in.',
  failed: 'Sign-in failed. The identity provider may be unavailable.',
};

export function App() {
  const route = useRoute();
  // undefined: still asking. null: there is no scan service (the static build).
  const [meta, setMeta] = useState<Meta | null>();
  const [session, setSession] = useState<SessionInfo | null>(null);
  const signInError = new URLSearchParams(window.location.search).get('signin_error');

  useEffect(() => {
    void api.meta().then(async (found) => {
      if (found) setSession(await api.session().catch(() => null));
      setMeta(found);
    });
  }, []);

  async function signOut() {
    const providerLogout = await api.signOut().catch(() => undefined);
    setSession(null);
    // Ending the session here leaves the identity provider's session alive; send the browser there to end that too.
    if (providerLogout) window.location.assign(providerLogout);
  }

  const view = route.path[0] ?? '';
  const scanViews = ['', 'recorded'].includes(view) || (view === 'scans' && route.path.length === 2);
  const current = (name: string) => (view === name || (name === '' && scanViews) ? 'page' : undefined);

  return (
    <>
      <header className="topbar">
        <a className="logo" href={href('')}>
          pq-oidc
        </a>
        <nav aria-label="Main">
          <a href={href('')} aria-current={current('')}>
            Scan
          </a>
          <a href={href('token')} aria-current={current('token')}>
            Token
          </a>
          <a href={href('learn')} aria-current={current('learn')}>
            How a login works
          </a>
          <a href={href('migrate')} aria-current={current('migrate')}>
            Migrate
          </a>
          {session && (
            <a href={href('scans')} aria-current={view === 'scans' && route.path.length === 1 ? 'page' : undefined}>
              Your scans
            </a>
          )}
        </nav>
        {meta && (
          <div className="account">
            {session ? (
              <>
                <span>{session.user.name ?? session.user.sub}</span>
                <button type="button" onClick={() => void signOut()}>
                  Sign out
                </button>
              </>
            ) : (
              <a className="button" href={api.signInUrl(`/${window.location.hash || '#/'}`)}>
                Sign in
              </a>
            )}
          </div>
        )}
      </header>

      <main>
        {signInError && (
          <p className="notice bad" role="alert">
            {SIGN_IN_ERRORS[signInError] ?? SIGN_IN_ERRORS.failed}
          </p>
        )}
        {meta === undefined ? null : scanViews ? (
          <ScanView route={route} meta={meta} session={session} />
        ) : view === 'scans' ? (
          <HistoryView session={session} />
        ) : view === 'compare' && route.path.length === 3 ? (
          <CompareView ids={[route.path[1]!, route.path[2]!]} session={session} />
        ) : view === 'token' ? (
          <TokenView meta={meta} session={session} />
        ) : view === 'learn' ? (
          <LearnView route={route} />
        ) : view === 'migrate' ? (
          <MigrateView route={route} session={session} />
        ) : (
          <section className="page">
            <h1>There is nothing at this address</h1>
            <p className="sub">
              <a href={href('')}>Go to the scanner</a>
            </p>
          </section>
        )}
      </main>

      <footer className="site">
        <p>
          The scanner reads what a server sends in a TLS handshake and what it publishes; it never signs in to anything. Built on FIPS 203 (ML-KEM), FIPS 204
          (ML-DSA), RFC 8446 (TLS 1.3) and OpenID Connect. <a href={REPO_URL}>Code and evidence on GitHub.</a>
        </p>
      </footer>
    </>
  );
}
