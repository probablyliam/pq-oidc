/**
 * Everything the API persists, behind one module (ADR 0008): users, sessions,
 * sign-in attempts, and scan jobs. SQLite through node:sqlite, so there is no
 * native build and no database server to run.
 *
 * The scans table is also the job queue. A worker claims a job and holds a
 * lease on it; if the worker dies the lease expires and the job is retried
 * once, then failed with a reason. Every query that returns a scan to a user
 * takes the user's ID: there is no way to read a scan without naming its owner.
 */
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type JobKind = 'scan' | 'issuer-keys';
export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed';

export interface User {
  id: string;
  issuer: string;
  sub: string;
  name: string | null;
  email: string | null;
}

export interface Session {
  userId: string;
  csrfToken: string;
  idToken: string | null;
  expiresAt: number;
}

export interface LoginAttempt {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
}

export interface ScanRow {
  id: string;
  userId: string;
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
  /** One-line summaries per layer, for list views. JSON. */
  summary: string | null;
  /** The full report. JSON. */
  result: string | null;
  errorCode: string | null;
  errorMessage: string | null;
}

const MIGRATIONS: string[] = [
  `
  CREATE TABLE users (
    id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    sub TEXT NOT NULL,
    name TEXT,
    email TEXT,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    UNIQUE (issuer, sub)
  );
  -- The primary key is a hash of the session ID, so a copy of this table is not a set of usable cookies.
  CREATE TABLE sessions (
    id_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    id_token TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE login_attempts (
    id_hash TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    nonce TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
    summary TEXT,
    result TEXT,
    error_code TEXT,
    error_message TEXT
  );
  CREATE INDEX scans_by_user ON scans (user_id, created_at DESC);
  CREATE INDEX scans_queue ON scans (status, created_at);
  CREATE INDEX scans_by_host ON scans (target_host, created_at);
  `,
];

const SCAN_COLUMNS = `id, user_id AS userId, kind, input, target_url AS targetUrl, target_host AS targetHost, status, created_at AS createdAt,
  started_at AS startedAt, finished_at AS finishedAt, attempts, progress, summary, result, error_code AS errorCode, error_message AS errorMessage`;

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

  // ---------------------------------------------------------------- users and sessions

  upsertUser(user: { id: string; issuer: string; sub: string; name: string | null; email: string | null }, now: number): User {
    return this.db
      .prepare(
        `INSERT INTO users (id, issuer, sub, name, email, created_at, last_seen_at) VALUES (:id, :issuer, :sub, :name, :email, :now, :now)
         ON CONFLICT (issuer, sub) DO UPDATE SET name = excluded.name, email = excluded.email, last_seen_at = excluded.last_seen_at
         RETURNING id, issuer, sub, name, email`,
      )
      .get({ ...user, now }) as unknown as User;
  }

  getUser(id: string): User | undefined {
    return this.db.prepare('SELECT id, issuer, sub, name, email FROM users WHERE id = ?').get(id) as User | undefined;
  }

  createSession(idHash: string, session: Session, now: number) {
    this.db
      .prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, id_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(idHash, session.userId, session.csrfToken, session.idToken, now, session.expiresAt);
  }

  getSession(idHash: string, now: number): Session | undefined {
    return this.db
      .prepare('SELECT user_id AS userId, csrf_token AS csrfToken, id_token AS idToken, expires_at AS expiresAt FROM sessions WHERE id_hash = ? AND expires_at > ?')
      .get(idHash, now) as Session | undefined;
  }

  deleteSession(idHash: string) {
    this.db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
  }

  saveLoginAttempt(idHash: string, attempt: LoginAttempt, expiresAt: number) {
    this.db
      .prepare('INSERT INTO login_attempts (id_hash, state, nonce, code_verifier, return_to, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(idHash, attempt.state, attempt.nonce, attempt.codeVerifier, attempt.returnTo, expiresAt);
  }

  /** Returns the attempt and deletes it: a sign-in attempt can be finished once. */
  takeLoginAttempt(idHash: string, now: number): LoginAttempt | undefined {
    return this.db
      .prepare('DELETE FROM login_attempts WHERE id_hash = ? AND expires_at > ? RETURNING state, nonce, code_verifier AS codeVerifier, return_to AS returnTo')
      .get(idHash, now) as LoginAttempt | undefined;
  }

  /** Removes expired sessions and sign-in attempts. */
  sweep(now: number) {
    this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
    this.db.prepare('DELETE FROM login_attempts WHERE expires_at <= ?').run(now);
  }

  // ---------------------------------------------------------------- scans, as their owner sees them

  createScan(scan: { id: string; userId: string; kind: JobKind; input: string; targetUrl: string; targetHost: string }, now: number): ScanRow {
    return this.db
      .prepare(
        `INSERT INTO scans (id, user_id, kind, input, target_url, target_host, status, created_at)
         VALUES (:id, :userId, :kind, :input, :targetUrl, :targetHost, 'queued', :now) RETURNING ${SCAN_COLUMNS}`,
      )
      .get({ ...scan, now }) as unknown as ScanRow;
  }

  getScan(userId: string, id: string): ScanRow | undefined {
    return this.db.prepare(`SELECT ${SCAN_COLUMNS} FROM scans WHERE id = ? AND user_id = ?`).get(id, userId) as ScanRow | undefined;
  }

  /** Newest first, without the full reports. */
  listScans(userId: string, limit: number, before?: number): Omit<ScanRow, 'result'>[] {
    return this.db
      .prepare(
        `SELECT ${SCAN_COLUMNS.replace(' result,', '')} FROM scans
         WHERE user_id = :userId AND kind = 'scan' AND created_at < :before ORDER BY created_at DESC LIMIT :limit`,
      )
      .all({ userId, limit, before: before ?? Number.MAX_SAFE_INTEGER }) as unknown as Omit<ScanRow, 'result'>[];
  }

  deleteScan(userId: string, id: string): boolean {
    return this.db.prepare('DELETE FROM scans WHERE id = ? AND user_id = ?').run(id, userId).changes > 0;
  }

  // ---------------------------------------------------------------- limits

  countUserScansSince(userId: string, since: number): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM scans WHERE user_id = ? AND created_at >= ?').get(userId, since) as { n: number }).n;
  }

  countUserActiveScans(userId: string): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM scans WHERE user_id = ? AND status IN ('queued', 'running')").get(userId) as { n: number }).n;
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
  finishJob(id: string, workerId: string, outcome: { result: string; summary: string } | { errorCode: string; errorMessage: string }, now: number): boolean {
    const succeeded = 'result' in outcome;
    return (
      this.db
        .prepare(
          `UPDATE scans SET status = :status, finished_at = :now, worker_id = NULL, lease_expires_at = NULL, progress = NULL,
             result = :result, summary = :summary, error_code = :errorCode, error_message = :errorMessage
           WHERE id = :id AND worker_id = :workerId AND status = 'running'`,
        )
        .run({
          id,
          workerId,
          now,
          status: succeeded ? 'succeeded' : 'failed',
          result: succeeded ? outcome.result : null,
          summary: succeeded ? outcome.summary : null,
          errorCode: succeeded ? null : outcome.errorCode,
          errorMessage: succeeded ? null : outcome.errorMessage,
        }).changes > 0
    );
  }
}
