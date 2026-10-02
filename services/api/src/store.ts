/**
 * Everything the API persists, behind one module (ADR 0008): scan jobs and
 * their results. SQLite through node:sqlite, so there is no native build and
 * no database server to run.
 *
 * There are no users (ADR 0014). A scan belongs to nobody; whoever holds its
 * ID can read it, and it is deleted after a day. The only thing kept about
 * the requester is a keyed hash of their address, for rate limiting.
 *
 * The scans table is also the job queue. A worker claims a job and holds a
 * lease on it; if the worker dies the lease expires and the job is retried
 * once, then failed with a reason.
 */
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type JobKind = 'scan' | 'issuer-keys';
export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed';

export interface ScanRow {
  id: string;
  kind: JobKind;
  input: string;
  targetUrl: string;
  targetHost: string;
  status: JobStatus;
  createdAt: number;
  startedAt: number | null;
  finishedAt: number | null;
  attempts: number;
  progress: string | null;
  /** The full report. JSON. */
  result: string | null;
  errorCode: string | null;
  errorMessage: string | null;
}

const MIGRATIONS: string[] = [
  `
  CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    -- A keyed hash of the requester's address. Used to count their recent scans; it is not the address.
    client TEXT NOT NULL,
    kind TEXT NOT NULL,
    input TEXT NOT NULL,
    target_url TEXT NOT NULL,
    target_host TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_expires_at INTEGER,
    worker_id TEXT,
    progress TEXT,
    result TEXT,
    error_code TEXT,
    error_message TEXT
  );
  CREATE INDEX scans_by_client ON scans (client, created_at);
  CREATE INDEX scans_queue ON scans (status, created_at);
  CREATE INDEX scans_by_target ON scans (target_url, created_at);
  CREATE INDEX scans_by_host ON scans (target_host, created_at);
  `,
];

const SCAN_COLUMNS = `id, kind, input, target_url AS targetUrl, target_host AS targetHost, status, created_at AS createdAt,
  started_at AS startedAt, finished_at AS finishedAt, attempts, progress, result, error_code AS errorCode, error_message AS errorMessage`;

export interface ClaimedJob {
  id: string;
  kind: JobKind;
  input: string;
  attempt: number;
}

export interface StoreOptions {
  /** A file path, or ":memory:". */
  path: string;
  /** How long a worker may hold a job without reporting progress. */
  leaseMs?: number;
  /** How many times a job is handed to a worker before it is failed. */
  maxAttempts?: number;
}

export class Store {
  private readonly db: DatabaseSync;
  private readonly leaseMs: number;
  private readonly maxAttempts: number;

  constructor(options: StoreOptions) {
    if (options.path !== ':memory:') mkdirSync(dirname(options.path), { recursive: true });
    this.db = new DatabaseSync(options.path);
    this.leaseMs = options.leaseMs ?? 90_000;
    this.maxAttempts = options.maxAttempts ?? 2;
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
    this.migrate();
  }

  private migrate() {
    const { user_version: version } = this.db.prepare('PRAGMA user_version').get() as { user_version: number };
    for (let i = version; i < MIGRATIONS.length; i++) {
      this.db.exec(`BEGIN; ${MIGRATIONS[i]} PRAGMA user_version = ${i + 1}; COMMIT;`);
    }
  }

  private transaction<T>(work: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = work();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  close() {
    this.db.close();
  }

  /** True if the database answers. Used by the readiness probe. */
  healthy(): boolean {
    try {
      this.db.prepare('SELECT 1').get();
      return true;
    } catch {
      return false;
    }
  }

  // ---------------------------------------------------------------- scans, as a visitor sees them

  createScan(scan: { id: string; client: string; kind: JobKind; input: string; targetUrl: string; targetHost: string }, now: number): ScanRow {
    return this.db
      .prepare(
        `INSERT INTO scans (id, client, kind, input, target_url, target_host, status, created_at)
         VALUES (:id, :client, :kind, :input, :targetUrl, :targetHost, 'queued', :now) RETURNING ${SCAN_COLUMNS}`,
      )
      .get({ ...scan, now }) as unknown as ScanRow;
  }

  getScan(id: string): ScanRow | undefined {
    return this.db.prepare(`SELECT ${SCAN_COLUMNS} FROM scans WHERE id = ?`).get(id) as ScanRow | undefined;
  }

  /**
   * The newest scan of exactly this address that is still fresh and did not
   * fail, whoever asked for it. Asking again for something just scanned gets
   * that answer instead of another round of connections to the target.
   */
  findRecent(kind: JobKind, targetUrl: string, since: number): ScanRow | undefined {
    return this.db
      .prepare(`SELECT ${SCAN_COLUMNS} FROM scans WHERE kind = ? AND target_url = ? AND created_at >= ? AND status != 'failed' ORDER BY created_at DESC LIMIT 1`)
      .get(kind, targetUrl, since) as ScanRow | undefined;
  }

  /** Deletes scans older than the retention period. Returns how many went. */
  purge(olderThan: number): number {
    return Number(this.db.prepare(`DELETE FROM scans WHERE created_at < ? AND status IN ('succeeded', 'failed')`).run(olderThan).changes);
  }

  // ---------------------------------------------------------------- limits

  countClientScansSince(client: string, since: number): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM scans WHERE client = ? AND created_at >= ?').get(client, since) as { n: number }).n;
  }

  countClientActiveScans(client: string): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM scans WHERE client = ? AND status IN ('queued', 'running')").get(client) as { n: number }).n;
  }

  /** Scans of one host by anyone: the limit that stops the service being used to hammer a third party. */
  countHostScansSince(host: string, since: number): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM scans WHERE target_host = ? AND created_at >= ?').get(host, since) as { n: number }).n;
  }

  queueDepth(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM scans WHERE status = 'queued'").get() as { n: number }).n;
  }

  countByStatus(): Record<string, number> {
    const rows = this.db.prepare('SELECT status, COUNT(*) AS n FROM scans GROUP BY status').all() as { status: string; n: number }[];
    return Object.fromEntries(rows.map((r) => [r.status, r.n]));
  }

  // ---------------------------------------------------------------- the queue, as a worker sees it

  /** Jobs whose worker stopped reporting: back to the queue, or failed if they have had their attempts. */
  private reapExpiredLeases(now: number) {
    this.db
      .prepare(
        `UPDATE scans SET status = 'failed', finished_at = :now, worker_id = NULL, lease_expires_at = NULL, error_code = 'worker-lost',
           error_message = 'The scanner stopped while working on this scan, twice. It was not retried again.'
         WHERE status = 'running' AND lease_expires_at < :now AND attempts >= :max`,
      )
      .run({ now, max: this.maxAttempts });
    this.db
      .prepare(`UPDATE scans SET status = 'queued', worker_id = NULL, lease_expires_at = NULL, progress = NULL WHERE status = 'running' AND lease_expires_at < :now`)
      .run({ now });
  }

  /** Hands the oldest queued job to a worker, with a lease. */
  claimJob(workerId: string, now: number): ClaimedJob | undefined {
    return this.transaction(() => {
      this.reapExpiredLeases(now);
      return this.db
        .prepare(
          `UPDATE scans SET status = 'running', attempts = attempts + 1, started_at = COALESCE(started_at, :now), worker_id = :workerId, lease_expires_at = :lease
           WHERE id = (SELECT id FROM scans WHERE status = 'queued' ORDER BY created_at LIMIT 1)
           RETURNING id, kind, input, attempts AS attempt`,
        )
        .get({ now, workerId, lease: now + this.leaseMs }) as ClaimedJob | undefined;
    });
  }

  /** Records a step and extends the lease. False if this worker no longer holds the job. */
  reportProgress(id: string, workerId: string, step: string, now: number): boolean {
    return (
      this.db
        .prepare(`UPDATE scans SET progress = :step, lease_expires_at = :lease WHERE id = :id AND worker_id = :workerId AND status = 'running'`)
        .run({ id, workerId, step, lease: now + this.leaseMs }).changes > 0
    );
  }

  /** Stores the outcome. False if this worker no longer holds the job (its lease expired and someone else has it). */
  finishJob(id: string, workerId: string, outcome: { result: string } | { errorCode: string; errorMessage: string }, now: number): boolean {
    const succeeded = 'result' in outcome;
    return (
      this.db
        .prepare(
          `UPDATE scans SET status = :status, finished_at = :now, worker_id = NULL, lease_expires_at = NULL, progress = NULL,
             result = :result, error_code = :errorCode, error_message = :errorMessage
           WHERE id = :id AND worker_id = :workerId AND status = 'running'`,
        )
        .run({
          id,
          workerId,
          now,
          status: succeeded ? 'succeeded' : 'failed',
          result: succeeded ? outcome.result : null,
          errorCode: succeeded ? null : outcome.errorCode,
          errorMessage: succeeded ? null : outcome.errorMessage,
        }).changes > 0
    );
  }
}
