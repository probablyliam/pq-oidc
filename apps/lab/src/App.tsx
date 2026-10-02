import { Ask } from './components/Ask.tsx';
import { Cost } from './components/Cost.tsx';
import { LoginLesson } from './components/LoginLesson.tsx';
import { MigrationSimulator } from './components/MigrationSimulator.tsx';
import { Rail } from './components/Rail.tsx';
import { Real } from './components/Real.tsx';
import { LINKS, REPO_URL } from './config.ts';

export function App() {
  return (
    <>
      <header className="topbar">
        <a className="logo" href="#ask">
          pq-oidc
        </a>
        <a href={REPO_URL}>Source on GitHub</a>
      </header>

      <div className="page">
        <Rail />
        <main>
          <Ask />
          <LoginLesson />
          <Cost />
          <MigrationSimulator />
          <Real />
        </main>
      </div>

      <footer className="site">
        <p>
          Everything on this page runs in your browser. Standards used: <a href={LINKS.fips204}>FIPS 204</a> (the new
          signature), <a href={LINKS.rfc9964}>RFC 9964</a> (how tokens carry it),{' '}
          <a href={LINKS.oidcCore}>OpenID Connect</a> (how logins work).
        </p>
      </footer>
    </>
  );
}
