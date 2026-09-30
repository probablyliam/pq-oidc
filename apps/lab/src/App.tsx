import { AttackPlayground } from './components/AttackPlayground.tsx';
import { Hero } from './components/Hero.tsx';
import { HowItWorks } from './components/HowItWorks.tsx';
import { MigrationSimulator } from './components/MigrationSimulator.tsx';
import { ProviderCheck } from './components/ProviderCheck.tsx';
import { RunIt } from './components/RunIt.tsx';
import { TokenCheck } from './components/TokenCheck.tsx';
import { LINKS, REPO_URL } from './config.ts';

export function App() {
  return (
    <>
      <header className="topbar">
        <div className="wrap">
          <a className="logo" href="#top">
            <img src={`${import.meta.env.BASE_URL}favicon.svg`} alt="" />
            pq-oidc
          </a>
          <nav aria-label="Sections">
            <a href="#provider">Check a provider</a>
            <a href="#token">Check a token</a>
            <a href="#how">How it works</a>
            <a href="#migrate">Migration</a>
            <a href="#attack">Attacks</a>
            <a className="gh" href={REPO_URL}>
              GitHub
            </a>
          </nav>
        </div>
      </header>

      <main id="top">
        <Hero />
        <ProviderCheck />
        <TokenCheck />
        <HowItWorks />
        <MigrationSimulator />
        <AttackPlayground />
        <RunIt />
      </main>

      <footer className="site">
        <div className="wrap">
          <span>pq-oidc · open source, MIT licensed · every check runs in your browser</span>
          <nav aria-label="Standards">
            <a href={LINKS.rfc9964}>RFC 9964</a>
            <a href={LINKS.fips204}>FIPS 204</a>
            <a href={LINKS.oidcCore}>OIDC Core</a>
            <a href={LINKS.oauth21}>OAuth 2.1</a>
            <a href={REPO_URL}>Source</a>
          </nav>
        </div>
      </footer>
    </>
  );
}
