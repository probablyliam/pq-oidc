# Final report

Written 2026-10-02, at the point the owner asked for the work to go to `main` and to the live site. Honest about what is verified and what is not.

## What was built

A tool that answers "is this login quantum-safe?" for an address a stranger types in, and shows its working.

- **A scanner** (`packages/scan-core`, `services/api`, `services/worker`). Given a site, it finds the login (the site's own link, then the usual addresses), opens TLS connections with its own TLS client, decrypts the handshake and verifies the server's signature, reads the certificate chain, the HTTP transport facts, and the OpenID Connect metadata and keys, and produces a report in which every statement is marked observed, inferred or could-not-determine. A plain-words summary puts one verdict and three questions on top (ADR 0012).
- **A web app** (`apps/web`). Paste an address, get the verdict; the technical groups fold open. A token checker that runs in the browser. A login lab: set what a site uses, log in with a made-up password, watch the three processes reveal with real values, then be the attacker and see what a quantum computer changes, with the working shown.
- **Deployment.** One container image for every service; Compose for the scanner (the identity provider as a profile); a Helm chart with the API and worker as separate pods, a PersistentVolumeClaim for SQLite, and NetworkPolicies that keep the worker off private ranges and give the API no egress. CI lints, typechecks, tests, builds the image, deploys to kind, scans through the cluster, and signs in to the demo apps.
- **The identity provider** the project started as (ML-DSA-65 ID tokens, per-app migration) is kept, with its evidence scripts (`prove`, `interop`) and findings.

## Where it departed from the brief, and why

The brief asked for sign-in before scanning, per-user history, a compare view and a migration exercise. The owner tried that version and rejected it: sign-in "defeats the purpose", saved scans and accounts were unwanted, the result page was overwhelming, the explainer was "a glorified video", the migration page was too much. The live reaction overrides the written brief (ADR 0014), so: no accounts, limits per visitor and per target instead; a verdict first; the explainer became a lab you drive; the migration page was cut (its model and tests remain in history at `411c1d6`).

The brief said never push to a remote. The owner lifted that on 2026-10-02 ("update the github and then get it all into prod"). Nothing is force-pushed and no history is rewritten.

## What is verified, and how

- **475 automated tests** (`npm test`): the address classifier against every blocked range and spelling, including IPv4-mapped, NAT64 and 6to4; the TLS 1.3 key schedule against the RFC 8448 trace; complete handshakes against OpenSSL 3.5 servers in every supported group, with Finished verified; whole scans of seven lab configurations with known right answers; hostile redirects, oversized bodies, slow servers, loops; the sign-in search; the service's limits, leases, retention and cross-site refusal; token attacks; the lab's cryptography (a typed password is read back only on a classical exchange; a forgery is accepted only against a classical signature).
- **Real sites, one scan each**: accounts.google.com, login.microsoftonline.com, github.com, netflix.com, youtube.com, www.cloudflare.com. Google and Microsoft are recognised as sign-in services with published keys; GitHub as a sign-in page; netflix.com and youtube.com have their login found from the bare domain.
- **In a real browser** (headless Edge, scripts in the untracked `.shots/`): every page at desktop, tablet and phone widths with no overflow; the home panel's slide; the lab's reveal and attack sequence at timed moments; symmetry of the lab's diagrams measured in SVG units; frame timing.

## What is not verified

- **The deployment has not run anywhere yet.** This machine has no Docker, kind or Helm, by the owner's rule against installing tools. The Dockerfile, Compose file and chart were written and proofread; the first CI run on `main` is their first run. Expect to fix something.
- **NetworkPolicy enforcement.** CI checks the manifests render as intended; kind's default CNI does not enforce them, so the egress restriction is proven only on a cluster with Calico or Cilium.
- **No independent security review** of the address boundary or the TLS parser took place. Two reviews were started by delegated agents and stopped at the owner's request to save tokens; the plan says to do it by reading.
- **No accessibility pass** with a screen reader; reduced-motion paths exist and were not tried by a person who needs them.
- **Firefox and Safari** were not used; everything was driven in Edge (Chromium).
- **The live site** (GitHub Pages) runs the app in static mode: the token checker and the lab work, scanning needs `npm start`. There is no free hosting for a service that opens raw TLS connections without an account the owner does not have.

## Known gaps worth closing next

In order: watch the first CI run and fix it; the security review by reading; a browser test in the repository; the accessibility pass; code-splitting the lab's cryptography out of the 560 kB bundle. Details in `docs/PLAN.md`.
