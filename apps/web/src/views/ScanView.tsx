import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { DEFAULT_POLICY, parseTarget, TargetRejected } from '@pq-oidc/scan-core/policy';
import type { ScanReport } from '@pq-oidc/scan-core/report';
import { api, ApiError } from '../api.ts';
import type { Meta, Scan, SessionInfo } from '../api.ts';
import { Report } from '../components/Report.tsx';
import { RECORDED } from '../recorded/index.ts';
import { href, navigate } from '../router.ts';
import type { Route } from '../router.ts';
import { ScanTable } from './ScanTable.tsx';

/** Lab servers are known by their port (see `npm run lab`). */
const LAB_NAMES: Record<string, string> = {
  '9441': 'classical',
  '9442': 'hybrid',
  '9443': 'hybrid only',
  '9444': 'post-quantum',
  '9445': 'TLS 1.2',
  '9446': 'RSA key transport',
  '9447': 'expired certificate',
};

interface Props {
  route: Route;
  /** Null when this copy of the site has no scan service behind it. */
  meta: Meta | null;
  session: SessionInfo | null;
}

function ScanForm({ meta, session, initial, compact }: { meta: Meta | null; session: SessionInfo | null; initial: string; compact: boolean }) {
  const [input, setInput] = useState(initial);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => setInput(initial), [initial]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    const target = input.trim();
    if (!target || !meta) return;
    // The same check the service makes, so a refusal is explained before anything is sent.
    try {
      parseTarget(target, { allowedPorts: meta.allowedPorts ?? DEFAULT_POLICY.allowedPorts, labOrigins: meta.labOrigins });
    } catch (reason) {
      if (reason instanceof TargetRejected) return setError(reason.message);
      throw reason;
    }
    if (!session) {
      window.location.assign(api.signInUrl(`/${href('', { target })}`));
      return;
    }
    setBusy(true);
    try {
      const scan = await api.createScan(target);
      navigate(`scans/${scan.id}`);
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : 'The scan could not be started.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="scan-form" onSubmit={submit}>
      <label htmlFor="target" className={compact ? 'sr-only' : undefined}>
        Address of a sign-in page or service
      </label>
      <div className="scan-row">
        <input
          id="target"
          type="text"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="https://login.example.com"
          spellCheck={false}
          autoComplete="url"
          autoCapitalize="none"
          disabled={!meta}
        />
        <button type="submit" className="primary" disabled={busy || !meta || !input.trim()}>
          {busy ? 'Starting…' : session || !meta ? 'Scan' : 'Sign in and scan'}
        </button>
      </div>
      {error && (
        <p className="notice bad" role="alert">
          {error}
        </p>
      )}
      {compact ? null : meta ? (
        <p className="examples">
          <span>Try:</span>
          {meta.labOrigins.map((origin) => (
            <button key={origin} type="button" className="link" onClick={() => setInput(origin)}>
              lab: {LAB_NAMES[new URL(origin).port] ?? new URL(origin).host}
            </button>
          ))}
          {['https://accounts.google.com', 'https://login.microsoftonline.com/common/v2.0'].map((url) => (
            <button key={url} type="button" className="link" onClick={() => setInput(url)}>
              {new URL(url).hostname}
            </button>
          ))}
        </p>
      ) : (
        <p className="notice">
          This copy of the site is static, so it cannot scan: a browser is not able to see a TLS handshake. The saved results below are from real scans. To scan
          something yourself, run the project (<code>npm start</code>).
        </p>
      )}
    </form>
  );
}

/** A scan that is queued or running, then its report. */
function LiveScan({ id }: { id: string }) {
  const [scan, setScan] = useState<Scan>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    setScan(undefined);
    setError(undefined);
    api.waitForScan(id, setScan, controller.signal).catch((reason: unknown) => {
      if (!controller.signal.aborted) setError(reason instanceof ApiError && reason.status === 404 ? 'There is no such scan, or it belongs to someone else.' : 'The scan could not be loaded.');
    });
    return () => controller.abort();
  }, [id]);

  if (error) return <p className="notice bad">{error}</p>;
  if (!scan) return <p className="fine">Loading…</p>;
  if (scan.status === 'failed') {
    return (
      <div className="panel progress">
        <h2>{scan.target}</h2>
        <p className="notice bad" role="alert">
          {scan.error?.message ?? 'The scan failed.'}
        </p>
        <p className="fine">Nothing was observed, so there is no report.</p>
      </div>
    );
  }
  if (scan.status !== 'succeeded' || !scan.report || !('schema' in scan.report)) {
    return (
      <div className="panel progress" aria-live="polite">
        <h2>{scan.target}</h2>
        <p className="step">
          <i className="pulse" aria-hidden="true" />
          {scan.status === 'queued' ? 'Waiting for a scanner' : (scan.progress ?? 'Starting')}
        </p>
      </div>
    );
  }
  return <Report report={scan.report} />;
}

export function ScanView({ route, meta, session }: Props) {
  const [recent, setRecent] = useState<Scan[]>();
  const scanId = route.path[0] === 'scans' ? route.path[1] : undefined;
  const recordedId = route.path[0] === 'recorded' ? route.path[1] : undefined;
  const recorded = RECORDED.find((r) => r.id === recordedId);

  useEffect(() => {
    if (session && !scanId && !recordedId) void api.listScans().then((scans) => setRecent(scans.slice(0, 5)), () => setRecent([]));
  }, [session, scanId, recordedId]);

  // With a report on screen the form steps back: the report is the page.
  const compact = Boolean(scanId || recorded);

  return (
    <>
      <section className={compact ? 'band compact' : 'band'}>
        {!compact && (
          <>
            <h1>What protects this login?</h1>
            <p className="sub">
              Scan a sign-in page. See the key exchange, the certificate and the token signature behind it, which of that was actually observed, and what a
              quantum computer would change for each.
            </p>
          </>
        )}
        <ScanForm meta={meta} session={session} initial={route.query.get('target') ?? ''} compact={compact} />
      </section>

      <section className="sheet">
        {scanId ? (
          session ? (
            <LiveScan id={scanId} />
          ) : (
            <p className="notice">
              <a href={api.signInUrl(`/${href(`scans/${scanId}`)}`)}>Sign in</a> to see this scan.
            </p>
          )
        ) : recorded ? (
          <Report report={recorded.report as ScanReport} recorded />
        ) : (
          <>
            {session && recent && recent.length > 0 && (
              <>
                <h2 className="section-title">Your recent scans</h2>
                <ScanTable rows={recent.map((scan) => ({ key: scan.id, link: href(`scans/${scan.id}`), host: scan.target, when: scan.createdAt, status: scan.status, layers: scan.layers }))} />
                <p className="list-actions">
                  <a href={href('scans')}>All scans, and compare two</a>
                </p>
              </>
            )}
            <h2 className="section-title">Saved results from real scans</h2>
            <p className="sub">Each row is one scan. No score: a sign-in has several layers, and they are not at the same risk.</p>
            <ScanTable
              rows={RECORDED.map((r) => ({ key: r.id, link: href(`recorded/${r.id}`), host: r.label, when: r.report.startedAt, status: 'succeeded' as const, layers: r.report.layers }))}
            />
          </>
        )}
      </section>
    </>
  );
}
