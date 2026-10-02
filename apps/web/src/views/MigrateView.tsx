import type { SessionInfo } from '../api.ts';
import type { Route } from '../router.ts';

export function MigrateView(_props: { route: Route; session: SessionInfo | null }) {
  return <section className="page"><h1>Migrate</h1></section>;
}
