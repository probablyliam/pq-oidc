import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { DEFAULT_POLICY, parseTarget, TargetRejected } from '@pq-oidc/scan-core/policy';
import { api, ApiError } from '../api.ts';
import type { Meta, Scan } from '../api.ts';
import { Report } from '../components/Report.tsx';
import { RECORDED } from '../recorded/index.ts';
import { href, navigate } from '../router.ts';
import type { Route } from '../router.ts';

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
const PUBLIC_EXAMPLES = ['accounts.google.com', 'login.microsoftonline.com', 'github.com/login'];

interface Props {
  route: Route;
  /** Null when this copy of the site has no scan service behind it. */
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
  // An example fills the box and runs: one press, one result.
  const example = (target: string) => {
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
          placeholder="Paste the address of a sign-in page"
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
      <p className="examples">
        <span>Try:</span>
        {PUBLIC_EXAMPLES.map((target) => (
          <button key={target} type="button" className="link" onClick={() => example(target)}>
            {target.split('/')[0]}
          </button>
        ))}
        {meta.labOrigins.map((origin) => (
          <button key={origin} type="button" className="link" onClick={() => example(origin)}>
            test server: {LAB_NAMES[new URL(origin).port] ?? new URL(origin).host}
          </button>
        ))}
      </p>
    </form>
  );
}

/** A scan that is queued or running, then its result. */
function LiveScan({ id, retentionHours }: { id: string; retentionHours: number }) {
  const [scan, setScan] = useState<Scan>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    setScan(undefined);
    setError(undefined);
    api.waitForScan(id, setScan, controller.signal).catch((reason: unknown) => {
      if (!controller.signal.aborted) setError(reason instanceof ApiError && reason.status === 404 ? 'This result is no longer available. Results are kept for a day.' : 'The result could not be loaded.');
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
  return <Report report={scan.report} retentionHours={retentionHours} />;
}

export function ScanView({ route, meta }: Props) {
  const scanId = route.path[0] === 'scan' ? route.path[1] : undefined;
  // Without a scan service there is always a saved result on screen, so the page shows what the tool does.
  const exampleId = route.path[0] === 'example' ? route.path[1] : !meta && !scanId ? RECORDED[0]!.id : undefined;
  const example = RECORDED.find((r) => r.id === exampleId);
  const showing = Boolean(scanId || route.path[0] === 'example');

  return (
    <>
      <section className={showing ? 'band compact' : 'band'}>
        {!showing && (
          <>
            <h1>Is this login quantum-safe?</h1>
            <p className="sub">Paste the address of any sign-in page. No account needed.</p>
          </>
        )}
        {meta ? (
          <ScanForm meta={meta} initial={route.query.get('target') ?? ''} />
        ) : (
          <p className="notice">
            This copy of the site cannot scan: a web page is not able to see how a connection is secured, so scanning needs the service that comes with the project. Below are saved
            results from real scans. To scan something yourself, run <code>npm start</code>.
          </p>
        )}
      </section>

      <section className="sheet">
        {scanId && meta ? (
          <LiveScan id={scanId} retentionHours={meta.retentionHours} />
        ) : example ? (
          <Report report={example.report} recorded />
        ) : (
          <div className="idle">
            <h2>What you get</h2>
            <ol className="answers preview">
              <li>
                <h3>If someone records this connection today, can they read it later?</h3>
              </li>
              <li>
                <h3>Can someone pretend to be this site?</h3>
              </li>
              <li>
                <h3>Can someone fake a sign-in?</h3>
              </li>
            </ol>
            <p className="fine">A plain answer to each, and the technical evidence underneath for anyone who wants to check it.</p>
          </div>
        )}

        {(!showing || !meta) && (
          <p className="saved">
            <span>{meta ? 'Or look at a saved result:' : 'Saved results:'}</span>
            {RECORDED.map((r) => (
              <a key={r.id} href={href(`example/${r.id}`)} aria-current={r.id === exampleId ? 'page' : undefined}>
                {r.label}
              </a>
            ))}
          </p>
        )}
      </section>
    </>
  );
}
