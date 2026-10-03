import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { DEFAULT_POLICY, parseTarget, TargetRejected } from '@pq-oidc/scan-core/policy';
import { api, ApiError } from '../api.ts';
import type { Meta, Scan } from '../api.ts';
import { Report } from '../components/Report.tsx';
import type { Route } from '../router.ts';

/** Two sign-in services, which publish their signing keys, and one ordinary login, which does not: both kinds of answer. */
const SITES = ['accounts.google.com', 'login.microsoftonline.com', 'github.com'];
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

/** What the page is doing: nothing yet, a scan under way, or a result (or a refusal) on screen. */
type Phase = { kind: 'idle' } | { kind: 'running'; target: string; step: string } | { kind: 'done'; scan: Scan } | { kind: 'refused'; target: string; message: string };

interface Props {
  route: Route;
  /** Null when no scan service answered. The form still shows; a scan explains itself if it cannot start. */
  meta: Meta | null;
}

function ScanForm({ meta, initial, busy, onScan }: { meta: Meta | null; initial: string; busy: boolean; onScan: (target: string) => void }) {
  const [input, setInput] = useState(initial);
  const [error, setError] = useState<string>();
  useEffect(() => setInput(initial), [initial]);

  function scan(target: string) {
    setError(undefined);
    if (!target) return;
    // The same check the service makes, so a refusal is explained before anything is sent.
    try {
      parseTarget(target, { allowedPorts: meta?.allowedPorts ?? DEFAULT_POLICY.allowedPorts, labOrigins: meta?.labOrigins ?? [] });
    } catch (reason) {
      if (reason instanceof TargetRejected) return setError(reason.message);
      throw reason;
    }
    onScan(target);
  }
  const submit = (event: FormEvent) => {
    event.preventDefault();
    scan(input.trim());
  };
  // A pick fills the box and runs: one press, one result.
  const pick = (target: string) => {
    setInput(target);
    scan(target);
  };

  return (
    <form className="scan-form" onSubmit={submit}>
      <label htmlFor="target" className="sr-only">
        Address of a site or its sign-in page
      </label>
      <div className="scan-row">
        <input id="target" type="text" value={input} onChange={(event) => setInput(event.target.value)} placeholder="accounts.example.com" spellCheck={false} autoComplete="url" autoCapitalize="none" />
        <button type="submit" className="primary" disabled={busy || !input.trim()}>
          {busy ? 'Scanning…' : 'Scan'}
        </button>
      </div>
      {error && (
        <p className="notice bad" role="alert">
          {error}
        </p>
      )}
      <dl className="picks">
        <div>
          <dt>Try a sign-in service, or a site</dt>
          <dd>
            {SITES.map((target) => (
              <button key={target} type="button" className="pick" disabled={busy} onClick={() => pick(target)}>
                {target}
              </button>
            ))}
          </dd>
        </div>
        {meta && meta.labOrigins.length > 0 && (
          <div>
            <dt>Or a local test server</dt>
            <dd>
              {meta.labOrigins.map((origin) => (
                <button key={origin} type="button" className="pick" disabled={busy} onClick={() => pick(origin)}>
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

function Outcome({ phase }: { phase: Exclude<Phase, { kind: 'idle' }> }) {
  if (phase.kind === 'running') {
    return (
      <div className="verdict verdict-pending" aria-live="polite">
        <p className="verdict-host">{phase.target}</p>
        <h2>Scanning…</h2>
        <p className="verdict-why step">
          <i className="pulse" aria-hidden="true" />
          {phase.step}
        </p>
      </div>
    );
  }
  if (phase.kind === 'refused' || phase.scan.status === 'failed') {
    const message = phase.kind === 'refused' ? phase.message : (phase.scan.error?.message ?? 'The scan failed.');
    return (
      <div className="verdict verdict-unknown">
        <p className="verdict-host">{phase.kind === 'refused' ? phase.target : phase.scan.target}</p>
        <h2>Could not scan this</h2>
        <p className="verdict-why" role="alert">
          {message}
        </p>
      </div>
    );
  }
  const report = phase.scan.report;
  if (!report || !('schema' in report)) return null;
  return <Report report={report} />;
}

export function ScanView({ route, meta }: Props) {
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const running = useRef<AbortController>(undefined);
  const ask = useRef<HTMLDivElement>(null);
  const lastTop = useRef<number>(undefined);
  const showing = phase.kind !== 'idle';

  async function scan(target: string) {
    running.current?.abort();
    const controller = (running.current = new AbortController());
    setPhase({ kind: 'running', target, step: 'Starting' });
    try {
      const scan = await api.scan(target, 'scan', (step) => setPhase({ kind: 'running', target, step }), controller.signal);
      if (!controller.signal.aborted) setPhase({ kind: 'done', scan });
    } catch (reason) {
      if (controller.signal.aborted) return;
      setPhase({ kind: 'refused', target, message: reason instanceof ApiError ? reason.message : 'The scan could not be started.' });
    }
  }
  useEffect(() => () => running.current?.abort(), []);

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
  }, [showing]);

  return (
    <section className={`sheet scan ${showing ? 'scanning' : 'idle'}`}>
      <div className="ask" ref={ask}>
        {!showing && (
          <>
            <h1>Is this login quantum-safe?</h1>
            <p className="sub">Paste a site, or its sign-in page.</p>
          </>
        )}
        <ScanForm meta={meta} initial={route.query.get('target') ?? ''} busy={phase.kind === 'running'} onScan={(target) => void scan(target)} />
      </div>

      {phase.kind !== 'idle' && (
        <div className="result" key={phase.kind === 'running' ? `run-${phase.target}` : 'result'}>
          <Outcome phase={phase} />
        </div>
      )}
    </section>
  );
}
