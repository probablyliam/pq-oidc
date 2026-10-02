# 5. A scanner backend behind the site, with a static mode

**Status:** accepted · 2026-10-02

## Context

The site's "check" ran entirely in the browser and read two public JSON documents. A browser cannot see the TLS version, key-exchange group or certificate of a connection, so the layer where post-quantum cryptography is actually deployed today (hybrid key exchange) was invisible. The site is also published on GitHub Pages, where there is no server.

## Decision

Add a backend that performs the scan, and keep the single-page app able to run without it.

- With the backend (`npm start`, Compose, Kubernetes): paste an address, get a result. No account (ADR 0014).
- Without it (GitHub Pages): the learning sections and token analysis work fully in the browser; the scan view shows recorded reports from real scans, dated and labelled as recordings, and says how to run the scanner.

The app asks `GET /api/v1/meta` once at start; no answer means static mode.

## Alternatives

- **Browser only.** Cannot observe TLS. Rejected: it was the main weakness.
- **Backend only, drop Pages.** Loses the public link that shows the work without setup.
- **A public hosted scanner.** Needs a paid host and turns an open scanner loose on the internet. Out of scope and against the project constraints.

## Consequences

- Two code paths in the scan view (live, recorded). The report component is the same for both.
- Recorded reports go stale; each shows its capture date.
