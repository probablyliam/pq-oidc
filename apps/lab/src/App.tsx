import { Checker } from './components/Checker.tsx';
import { Cost } from './components/Cost.tsx';
import { LoginScene } from './components/LoginScene.tsx';
import { More } from './components/More.tsx';
import { SwitchGame } from './components/SwitchGame.tsx';
import { LINKS, REPO_URL } from './config.ts';

export function App() {
  return (
    <>
      <header className="topbar">
        <a className="logo" href="#check">
          pq-oidc
        </a>
        <nav aria-label="On this page">
          <a href="#check">Check</a>
          <a href="#how">What it means</a>
          <a href="#catch">Why not yet</a>
          <a href="#switch">Make the switch</a>
          <a href={REPO_URL}>GitHub</a>
        </nav>
      </header>

      <main>
        <Checker />
        <LoginScene />
        <Cost />
        <SwitchGame />
        <More />
      </main>

      <footer className="site">
        <p>
          Everything on this page runs in your browser. Built on <a href={LINKS.fips204}>FIPS 204</a> (the quantum-proof
          signature, ML-DSA), <a href={LINKS.rfc9964}>RFC 9964</a> (how login tokens carry it) and{' '}
          <a href={LINKS.oidcCore}>OpenID Connect</a>.
        </p>
      </footer>
    </>
  );
}
