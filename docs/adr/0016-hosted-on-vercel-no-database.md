# 16. The live site runs the scanner inside a Vercel Function, with no database

**Status:** accepted · 2026-10-02

## Context

The site on GitHub Pages could not scan: Pages serves files only, and a scan opens TLS connections. The owner: "I dont want this site to be just a static site then I want it to be real and work ... I just want 1 version of the site where people can load it up and use it like a tool", on a Vercel account they already have, and "I'd rather avoid doing a database if thats possible".

## Decision

- **One Vercel project** serves the web app as static files and the scanner as a Vercel Function (`api/v1/scan.js`, with `api/v1/meta.js` beside it). Vercel Functions on the Node.js runtime run Node 24, which has ML-KEM and ML-DSA in `node:crypto` since 24.7, and allow outbound sockets, so the scanner's own TLS client runs there unchanged.
- **The scan runs inside the request.** The function streams each step as a line of JSON while it works, then the finished scan, and closes. Nothing is written anywhere: a result exists only in the response that carried it. `maxDuration` is 60 s; a scan is budgeted 45 s and usually takes 2–4 s.
- **No database.** The limits that stood in for accounts (ADR 0014) are kept in the memory of the function instance: per visitor, per scanned service, a repeat-within-five-minutes cache, and a ceiling on scans running at once. Vercel's Fluid compute shares an instance between concurrent requests and keeps it warm, so the limits hold for ordinary use; they are not a guarantee across instances or restarts, and the honest statement of that is in the threat model.
- **One protocol for the web app.** The self-hosted API gains the same streaming route (`POST /api/v1/scan`), relaying the worker's progress from the job row, so the page speaks one protocol whether it is served by Vercel, `npm start`, Compose or the Helm chart. The queued routes stay for the CLI and CI.
- **The function is committed as a bundle.** `services/vercel/src/scan.ts` is the source; `npm run vercel:bundle` (rolldown, a project-local dev dependency) writes `api/v1/scan.js` as one plain ESM file with only `node:` and `@noble/hashes` imports, so Vercel's build has no workspace TypeScript to resolve. CI fails if the committed bundle differs from what the source produces, and runs the tests on Node 24 as well as 25.
- **GitHub Pages is retired.** There is one site.

## Alternatives

- **Keep the API + worker on a host with a volume** (Fly.io, Render, a VM). Keeps the privilege split and result links; needs a new account, a container host and a volume, for a tool whose results are deliberately not kept. The chart and Compose file remain for anyone who wants that.
- **A key-value store for the limits** (Vercel KV, Upstash). Exact limits across instances; a database the owner asked to avoid, for a limit that only needs to be good enough.
- **Cloudflare Workers.** No raw TCP sockets with a custom ClientHello; the TLS observer cannot run there.

## Consequences

- Scanning works on the public site, which is the point.
- The per-visitor and per-site limits are best-effort on Vercel. The scanner itself still refuses private addresses and bounds every connection, which is what protects third parties and the host; the limits only bound cost.
- No worker split and no NetworkPolicy on Vercel: the function that parses hostile bytes is the function that answers the visitor. It holds nothing but the request in hand, so there is nothing for a compromised scan to read.
- Results cannot be linked to; a page refresh means a new scan.
