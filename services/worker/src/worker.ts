/**
 * The worker: claims a job from the API, runs it, reports the result.
 *
 * It is the only part of the system that connects to scan targets, and it is
 * given nothing else: no database, no session secrets, only a token for the
 * API's job queue. If its handling of hostile bytes is ever wrong, what an
 * attacker reaches is this process and the jobs it holds (ADR 0008).
 */
import { fetchIssuerKeys, runScan, TargetRejected } from '@pq-oidc/scan-core';
import type { Lookup, TargetPolicy } from '@pq-oidc/scan-core';

export type WorkerLog = (level: 'info' | 'warn' | 'error', message: string, fields?: Record<string, unknown>) => void;

export interface WorkerOptions {
  /** The API's internal listener, e.g. http://api:8081. */
  apiUrl: string;
  token: string;
  workerId: string;
  policy: TargetPolicy;
  /** How long to wait before asking again when the queue is empty. */
  pollMs?: number;
  /** Jobs run at once. */
  concurrency?: number;
  lookup?: Lookup;
  log?: WorkerLog;
}

interface Job {
  id: string;
  kind: 'scan' | 'issuer-keys';
  input: string;
  attempt: number;
}

const reason = (error: unknown) => (error instanceof Error ? error.message : String(error));

export function startWorker(options: WorkerOptions) {
  const log: WorkerLog = options.log ?? (() => {});
  const pollMs = options.pollMs ?? 1000;
  let stopping = false;
  const wakers = new Set<() => void>();

  const call = (path: string, body: unknown): Promise<Response> =>
    fetch(`${options.apiUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${options.token}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });

  async function run(job: Job) {
    const started = Date.now();
    let leaseLost = false;
    let lastStep = Promise.resolve();
    // Progress doubles as the heartbeat that keeps the lease. Sent in order; the scan never waits for it.
    const progress = (step: string) => {
      lastStep = lastStep
        .then(() => call(`/internal/v1/jobs/${job.id}/progress`, { workerId: options.workerId, step }))
        .then((response) => {
          if (response.status === 409) leaseLost = true;
        })
        .catch(() => {});
    };

    let body: Record<string, unknown>;
    try {
      const result =
        job.kind === 'issuer-keys'
          ? await fetchIssuerKeys(job.input, { policy: options.policy, lookup: options.lookup })
          : await runScan(job.input, { policy: options.policy, lookup: options.lookup, onProgress: progress });
      body = { status: 'succeeded', result };
    } catch (error) {
      if (error instanceof TargetRejected) {
        body = { status: 'failed', error: { code: error.code, message: error.message } };
      } else {
        // Details stay in the worker's log. The user is told only that it failed.
        log('error', 'scan crashed', { scanId: job.id, error: reason(error) });
        body = { status: 'failed', error: { code: 'scanner-error', message: 'The scanner hit an internal error on this target.' } };
      }
    }
    await lastStep;
    if (leaseLost) return log('warn', 'lease lost; result discarded', { scanId: job.id });
    const response = await call(`/internal/v1/jobs/${job.id}/result`, { workerId: options.workerId, durationMs: Date.now() - started, ...body });
    log(response.ok ? 'info' : 'warn', response.ok ? 'job done' : 'result not accepted', { scanId: job.id, status: body.status, http: response.status, ms: Date.now() - started });
  }

  async function loop() {
    while (!stopping) {
      let job: Job | undefined;
      try {
        const response = await call('/internal/v1/jobs/claim', { workerId: options.workerId });
        if (response.status === 200) job = ((await response.json()) as { job: Job }).job;
        else if (response.status !== 204) log('warn', 'claim refused', { http: response.status });
      } catch (error) {
        log('warn', 'cannot reach the API', { error: reason(error) });
      }
      if (job) {
        const { id } = job;
        await run(job).catch((error: unknown) => log('error', 'could not report a result', { scanId: id, error: reason(error) }));
      } else if (!stopping) {
        await new Promise<void>((resolve) => {
          const done = () => {
            clearTimeout(timer);
            wakers.delete(done);
            resolve();
          };
          const timer = setTimeout(done, pollMs);
          wakers.add(done);
        });
      }
    }
  }

  const loops = Array.from({ length: options.concurrency ?? 2 }, loop);
  return {
    /** Stops claiming new jobs and waits for the ones in flight. */
    async stop() {
      stopping = true;
      for (const wake of [...wakers]) wake();
      await Promise.all(loops);
    },
  };
}
