import { useState } from 'react';
import { Checker } from './components/Checker.tsx';
import { Cost } from './components/Cost.tsx';
import { Migrate } from './components/Migrate.tsx';
import { More } from './components/More.tsx';
import { LINKS, REPO_URL } from './config.ts';
import type { Mode } from './lab/crypto.ts';
import { Labs } from './lab/Labs.tsx';

export function App() {
  // One mode for the whole page, so a result in the tool can open the lab showing the same cryptography.
  const [mode, setMode] = useState<Mode>('classical');

  function seeInLab(next: Mode) {
    setMode(next);
    document.getElementById('lab')?.scrollIntoView();
  }

  return (
    <>
      <header className="topbar">
        <a className="logo" href="#check">
          pq-oidc
        </a>
        <nav aria-label="On this page">
          <a href="#check">Check</a>
          <a href="#lab">How a login works</a>
          <a href="#attack">Break it</a>
          <a href="#catch">Why not yet</a>
          <a href="#migrate">Migrate</a>
          <a href={REPO_URL}>GitHub</a>
        </nav>
      </header>

      <main>
        <Checker onSeeInLab={seeInLab} />
        <div className="learn">
          <Labs mode={mode} onMode={setMode} />
          <Cost />
          <Migrate />
          <More />
        </div>
      </main>

      <footer className="site">
        <p>
          Everything on this page runs in your browser. Built on <a href={LINKS.fips203}>FIPS 203</a> (ML-KEM),{' '}
          <a href={LINKS.fips204}>FIPS 204</a> (ML-DSA), <a href={LINKS.rfc9964}>RFC 9964</a> (ML-DSA in login tokens)
          and <a href={LINKS.oidcCore}>OpenID Connect</a>.
        </p>
      </footer>
    </>
  );
}
