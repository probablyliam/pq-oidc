# 8. API and worker as separate processes; jobs pulled over HTTP; SQLite

**Status:** accepted · 2026-10-02

## Context

A scan opens around fifteen connections with timeouts and can take tens of seconds, so it cannot run inside the request that asked for it. The code that runs a scan parses bytes from arbitrary servers. The code that serves the API holds sessions, ID tokens and every user's history.

## Decision

- **Jobs.** `POST /api/v1/scans` writes a `queued` row and returns `202` with an ID. The client polls `GET /api/v1/scans/:id`.
- **Two processes.** `services/api` owns the database and never connects to a target. `services/worker` has no database; it claims a job from the API (`POST /internal/v1/jobs/claim`), runs it, reports progress and posts the result. The internal API listens on a separate port and requires a bearer token.
- **Leases.** A claimed job has a lease. If the worker dies, the lease expires and the job is retried once, then failed with a reason.
- **SQLite through `node:sqlite`.** One file, WAL mode, a PersistentVolumeClaim in Kubernetes, one API replica.

## Why the split

In Kubernetes a NetworkPolicy applies to a pod. Putting the scanner in its own pod means the part with internet egress has no user data, and the part with user data has no internet egress. A compromised worker can report false results for jobs it holds; it cannot read sessions or other users' scans.

## Alternatives

- **In-process worker.** Simpler, but one pod then needs both the database and open egress.
- **Redis or a message broker.** The database is already a durable queue at this scale; a broker would be one more thing to run, secure and explain, with no problem to solve.
- **Postgres.** The right choice for more than one API replica. It needs a container to develop against, which this machine does not have, so it could not be verified. Storage sits behind one module (`services/api/src/store.ts`) so it can be swapped.
- **Server-sent events for progress.** Polling every second is enough for a job that lasts under a minute.

## Consequences

- One API replica. Stated in the chart and the report.
- `node:sqlite` is still marked experimental in Node 24/25; it needs no native build and no extra dependency.
- The worker token is a shared secret between two deployments.
