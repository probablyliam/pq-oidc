import { useEffect, useState } from 'react';
import type { ScanReport } from '@pq-oidc/scan-core/report';
import { api } from '../api.ts';
import type { Scan, SessionInfo } from '../api.ts';
import { EXPOSURE } from '../components/Report.tsx';
import { href, navigate } from '../router.ts';
import { ScanTable } from './ScanTable.tsx';

/** Every scan the signed-in user has run. Tick two to compare them. */
export function HistoryView({ session }: { session: SessionInfo | null }) {
  const [scans, setScans] = useState<Scan[]>();
  const [picked, setPicked] = useState<string[]>([]);
  const [error, setError] = useState(false);

  const load = () => api.listScans().then(setScans, () => setError(true));
  useEffect(() => {
    if (session) void load();
  }, [session]);

  if (!session) {
    return (
      <section className="page">
        <h1>Your scans</h1>
        <p className="sub">
          <a href={api.signInUrl(`/${href('scans')}`)}>Sign in</a> to see the scans you have run.
        </p>
      </section>
    );
  }

  // Ticking a third box replaces the oldest tick: there are never more than two selected.
  const toggle = (id: string) => setPicked((now) => (now.includes(id) ? now.filter((x) => x !== id) : [...now, id].slice(-2)));

  async function remove() {
    await Promise.all(picked.map((id) => api.deleteScan(id).catch(() => undefined)));
    setPicked([]);
    await load();
  }

  return (
    <section className="page">
      <h1>Your scans</h1>
      <p className="sub">Only you can see these. Tick two to see what changed between them.</p>
      {error && <p className="notice bad">The list could not be loaded.</p>}
      {scans && scans.length === 0 && (
        <p className="notice">
          Nothing yet. <a href={href('')}>Scan a sign-in page</a>.
        </p>
      )}
      {scans && scans.length > 0 && (
        <>
          <div className="list-actions">
            <button type="button" className="primary" disabled={picked.length !== 2} onClick={() => navigate(`compare/${picked[0]}/${picked[1]}`)}>
              Compare the two ticked scans
            </button>
            <button type="button" className="danger" disabled={picked.length === 0} onClick={() => void remove()}>
              Delete ticked
            </button>
          </div>
          <ScanTable
            lead="Pick"
            rows={scans.map((scan) => ({
              key: scan.id,
              link: href(`scans/${scan.id}`),
              host: scan.target,
              when: scan.createdAt,
              status: scan.status,
              layers: scan.layers,
              lead: <input type="checkbox" aria-label={`Select the scan of ${scan.target}`} checked={picked.includes(scan.id)} onChange={() => toggle(scan.id)} />,
            }))}
          />
        </>
      )}
    </section>
  );
}

/** Two reports side by side: each layer, then every finding whose wording differs. */
export function CompareView({ ids, session }: { ids: [string, string]; session: SessionInfo | null }) {
  const [reports, setReports] = useState<[ScanReport, ScanReport]>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (!session) return;
    setReports(undefined);
    Promise.all(ids.map((id) => api.getScan(id))).then(
      ([a, b]) => {
        const [left, right] = [a?.report, b?.report];
        if (left && right && 'schema' in left && 'schema' in right) setReports([left, right]);
        else setError('Both scans have to be finished to be compared.');
      },
      () => setError('One of these scans could not be loaded.'),
    );
  }, [ids[0], ids[1], session]);

  if (!session) {
    return (
      <section className="page">
        <h1>Compare two scans</h1>
        <p className="sub">
          <a href={api.signInUrl(`/${href(`compare/${ids[0]}/${ids[1]}`)}`)}>Sign in</a> to compare your scans.
        </p>
      </section>
    );
  }
  if (error) {
    return (
      <section className="page">
        <h1>Compare two scans</h1>
        <p className="notice bad">{error}</p>
      </section>
    );
  }
  if (!reports) return <section className="page">Loading…</section>;

  const [a, b] = reports;
  const title = (r: ScanReport) => `${r.target.hostname}, ${new Date(r.startedAt).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}`;
  const ids2 = [...new Set([...a.findings, ...b.findings].map((f) => f.id))];
  const changed = ids2
    .map((id) => ({ id, was: a.findings.find((f) => f.id === id), now: b.findings.find((f) => f.id === id) }))
    .filter(({ was, now }) => was?.title !== now?.title);

  return (
    <section className="page">
      <h1>What differs between these two scans</h1>
      <div className="scroll-x">
        <table className="compare">
          <thead>
            <tr>
              <th>Layer</th>
              <th>
                <a href={href(`scans/${ids[0]}`)}>{title(a)}</a>
              </th>
              <th>
                <a href={href(`scans/${ids[1]}`)}>{title(b)}</a>
              </th>
            </tr>
          </thead>
          <tbody>
            {a.layers.map((layer) => {
              const other = b.layers.find((l) => l.id === layer.id);
              return (
                <tr key={layer.id} className={other?.headline !== layer.headline || other.exposure !== layer.exposure ? 'changed' : ''}>
                  <td>{layer.name}</td>
                  {[layer, other].map((l, i) => (
                    <td key={i}>
                      {l?.headline}
                      <br />
                      <span className="fine">{l ? EXPOSURE[l.exposure] : ''}</span>
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <h2 className="section-title">Findings that differ</h2>
      {changed.length === 0 ? (
        <p className="sub">None. Every finding reads the same in both scans.</p>
      ) : (
        <ul className="diff-list">
          {changed.map(({ id, was, now }) => (
            <li key={id}>
              {was && <p className="was">{was.title}</p>}
              <p>{now ? now.title : 'Not in the second scan.'}</p>
              {!was && <p className="fine">Not in the first scan.</p>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
