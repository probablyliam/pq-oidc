import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { DEFAULT_POLICY, parseTarget, TargetRejected } from '@pq-oidc/scan-core/policy';
import { api, ApiError } from '../api.ts';
import type { Meta, Scan } from '../api.ts';
import { Report } from '../components/Report.tsx';
import { navigate } from '../router.ts';
import type { Route } from '../router.ts';

const SITES = ['accounts.google.com', 'login.microsoftonline.com', 'github.com/login'];
/** Local test servers are known by their port (see `npm run lab`). */
const TEST_SERVERS: Record<string, string> = {
  '9441': 'Classical',
  '9442': 'Hybrid',
  '9443': 'Hybrid only',
  '9444': 'Post-quantum',
  '9445': 'TLS 1.2',
  '9446': 'RSA key transport',
  '9447': 'Expired certificate',
};

interface Props {
  route: Route;
  /** Null when there is no scan service behind this page. */
  meta: Meta | null;
}

function ScanForm({ meta, initial }: { meta: Meta; initial: string }) {
  const [input, setInput] = useState(initial);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => setInput(initial), [initial]);

  async function scan(target: string) {
    setError(undefined);
    if (!target) return;
    // The same check the service makes, so a refusal is explained before anything is sent.
    try {
      parseTarget(target, { allowedPorts: meta.allowedPorts ?? DEFAULT_POLICY.allowedPorts, labOrigins: meta.labOrigins });
    } catch (reason) {
      if (reason instanceof TargetRejected) return setError(reason.message);
      throw reason;
    }
    setBusy(true);
    try {
      const started = await api.createScan(target);
      navigate(`scan/${started.id}`);
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : 'The scan could not be started.');
    } finally {
      setBusy(false);
    }
  }

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void scan(input.trim());
  };
  // A pick fills the box and runs: one press, one result.
  const pick = (target: string) => {
    setInput(target);
    void scan(target);
  };

  return (
    <form className="scan-form" onSubmit={submit}>
      <label htmlFor="target" className="sr-only">
        Address of a sign-in page
      </label>
      <div className="scan-row">
        <input
          id="target"
          type="text"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="accounts.example.com"
          spellCheck={false}
          autoComplete="url"
          autoCapitalize="none"
        />
        <button type="submit" className="primary" disabled={busy || !input.trim()}>
          {busy ? 'Starting…' : 'Scan'}
        </button>
      </div>
      {error && (
        <p className="notice bad" role="alert">
          {error}
        </p>
      )}
      <dl className="picks">
        <div>
          <dt>Try a site</dt>
          <dd>
            {SITES.map((target) => (
              <button key={target} type="button" className="pick" onClick={() => pick(target)}>
                {target.split('/')[0]}
              </button>
            ))}
          </dd>
        </div>
        {meta.labOrigins.length > 0 && (
          <div>
            <dt>Or a local test server</dt>
            <dd>
              {meta.labOrigins.map((origin) => (
                <button key={origin} type="button" className="pick" onClick={() => pick(origin)}>
                  {TEST_SERVERS[new URL(origin).port] ?? new URL(origin).host}
                </button>
              ))}
            </dd>
          </div>
        )}
      </dl>
    </form>
  );
}

/** A scan that is queued or running, then its result. */
function LiveScan({ id }: { id: string }) {
  const [scan, setScan] = useState<Scan>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    setScan(undefined);
    setError(undefined);
    api.waitForScan(id, setScan, controller.signal).catch((reason: unknown) => {
      if (!controller.signal.aborted) setError(reason instanceof ApiError && reason.status === 404 ? 'This result has gone. Scan the address again.' : 'The result could not be loaded.');
    });
    return () => controller.abort();
  }, [id]);

  if (error) return <p className="notice bad">{error}</p>;
  if (!scan) return <p className="fine">Loading…</p>;
  if (scan.status === 'failed') {
    return (
      <div className="verdict verdict-unknown">
        <p className="verdict-host">{scan.target}</p>
        <h2>Could not scan this</h2>
        <p className="verdict-why" role="alert">
          {scan.error?.message ?? 'The scan failed.'}
        </p>
      </div>
    );
  }
  if (scan.status !== 'succeeded' || !scan.report || !('schema' in scan.report)) {
    return (
      <div className="verdict verdict-pending" aria-live="polite">
        <p className="verdict-host">{scan.target}</p>
        <h2>Scanning…</h2>
        <p className="verdict-why step">
          <i className="pulse" aria-hidden="true" />
          {scan.status === 'queued' ? 'Waiting for a scanner' : (scan.progress ?? 'Starting')}
        </p>
      </div>
    );
  }
  return <Report report={scan.report} />;
}

export function ScanView({ route, meta }: Props) {
  const scanId = route.path[0] === 'scan' ? route.path[1] : undefined;
  const ask = useRef<HTMLDivElement>(null);
  const lastTop = useRef<number>(undefined);

  // The question sits in the middle of the page until a scan starts, then at the top with the result
  // below. Measure where it was and slide it from there, so the move reads as the page making room.
  useLayoutEffect(() => {
    const panel = ask.current;
    if (!panel) return;
    const top = panel.getBoundingClientRect().top + window.scrollY;
    const from = lastTop.current;
    lastTop.current = top;
    if (from === undefined || Math.abs(from - top) < 1 || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    panel.style.transition = 'none';
    panel.style.transform = `translateY(${from - top}px)`;
    const frame = requestAnimationFrame(() => {
      panel.style.transition = 'transform 0.45s cubic-bezier(0.2, 0.7, 0.3, 1)';
      panel.style.transform = '';
    });
    return () => cancelAnimationFrame(frame);
  }, [scanId]);

  return (
    <section className={`sheet scan ${scanId ? 'scanning' : 'idle'}`}>
      <div className="ask" ref={ask}>
        {!scanId && (
          <>
            <h1>Is this login quantum-safe?</h1>
            <p className="sub">Paste the address of a sign-in page.</p>
          </>
        )}
        {meta ? (
          <ScanForm meta={meta} initial={route.query.get('target') ?? ''} />
        ) : (
          <p className="notice">
            Scanning is done by a small service that runs beside this page, and it is not running here. Start the project with <code>npm start</code> to scan.
          </p>
        )}
      </div>

      {scanId && meta && (
        <div className="result" key={scanId}>
          <LiveScan id={scanId} />
        </div>
      )}
    </section>
  );
}
