import { useEffect, useState } from 'react';
import { api } from './api.ts';
import type { Meta } from './api.ts';
import { href, useRoute } from './router.ts';
import { LearnView } from './views/LearnView.tsx';
import { ScanView } from './views/ScanView.tsx';
import { TokenView } from './views/TokenView.tsx';

const REPO_URL = 'https://github.com/probablyliam/pq-oidc';

export function App() {
  const route = useRoute();
  // undefined: still asking. null: there is no scan service (the static build).
  const [meta, setMeta] = useState<Meta | null>();

  useEffect(() => {
    void api.meta().then(setMeta);
  }, []);

  const view = route.path[0] ?? '';
  const scanViews = ['', 'scan', 'example'].includes(view);
  const current = (name: string) => (view === name || (name === '' && scanViews) ? 'page' : undefined);

  return (
    <>
      <header className="topbar">
        <a className="logo" href={href('')}>
          pq-oidc
        </a>
        <nav aria-label="Main">
          <a href={href('')} aria-current={current('')}>
            Scan a login
          </a>
          <a href={href('token')} aria-current={current('token')}>
            Check a token
          </a>
          <a href={href('learn')} aria-current={current('learn')}>
            How a login works
          </a>
        </nav>
        <a className="repo" href={REPO_URL}>
          GitHub
        </a>
      </header>

      <main>
        {meta === undefined ? null : scanViews ? (
          <ScanView route={route} meta={meta} />
        ) : view === 'token' ? (
          <TokenView meta={meta} />
        ) : view === 'learn' ? (
          <LearnView route={route} />
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
          The scanner reads what a server sends in a TLS handshake and what it publishes; it never signs in to anything and keeps no accounts. Built on FIPS 203 (ML-KEM), FIPS 204
          (ML-DSA), RFC 8446 (TLS 1.3) and OpenID Connect. <a href={REPO_URL}>Code and evidence on GitHub.</a>
        </p>
      </footer>
    </>
  );
}
