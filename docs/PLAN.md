# Plan

Source of truth for the rebuild, done on branch `scanner-platform` and merged to `main` on 2026-10-02 at the owner's request.
Decisions with reasoning live in [`docs/adr/`](adr/).

## Status

| Phase | What | Status |
|---|---|---|
| 0 | Inspect, run, assess, plan | done |
| 1 | Scan core: target policy, SSRF-safe resolver and connector | done |
| 2 | Real analysis: TLS handshake observer, certificates, HTTP transport, OIDC metadata, report | done; finding the login from a bare site added later (ADR 0015) |
| 3 | Token analysis with real verification | done |
| 4 | API service, job model, persistence, worker | done, then reworked: no accounts (ADR 0014) |
| 5 | Results UI | done, then reworked: verdict first, technical detail folded away (ADR 0012) |
| 6 | Login explainer | done, then reworked twice into the login lab (ADR 0011) |
| 7 | Migration exercise | cut at the owner's request (ADR 0014); model and tests remain in history at `411c1d6` |
| 8 | Docker, Compose, Helm (NetworkPolicy), CI, Pages | done; the cluster job runs in CI only (no Docker on this machine) |
| 9 | Hardening | partly: dependency audit in CI, phone layouts checked; no independent security review, no accessibility pass |
| 10 | README, threat model, final report | done |

## Next steps

Everything the owner asked for is in. What remains, in the order it is worth doing:

1. **Watch the first CI run on `main`.** The image build, the kind deployment, the scan through the cluster and the Pages deploy have never run before this push; fix what they find.
2. **Independent security review** of the address boundary (`packages/scan-core/src/net`), the TLS parser against hostile input (`packages/scan-core/src/tls`), and the API's limits. Done by reading, not by delegating.
3. **A browser test in the repository** (`tests/browser/`, playwright-core, `msedge` locally and `chrome` in CI): scan a lab server and read the verdict; the token page; the lab's reveal and attack sequence, which were verified by hand with the scripts in the untracked `.shots/`.
4. **Accessibility pass**: focus order, contrast, labels for the lab's diagrams, reduced motion (the code paths exist; they were not tried with a screen reader).
5. **Bundle size**: the web app is one 560 kB script; the lab's cryptography could load on demand.

Useful commands: `npm start` (scanner, worker and test servers; open http://localhost:8080), `npm run dev`, `npm run lab`, `npm run oidc` (the ML-DSA identity provider, separate from the scanner), `npm test`, `npm run scan -- <url>`, `npm run typecheck`, `npx eslint .`, `node scripts/probe-page.ts <url>` (what the scanner sees on a page).

---

## Phase 0 assessment (2026-10-02)

### 1. What the project is today

`pq-oidc` is a monorepo with four parts:

- **A static site** (`apps/lab`, React + Vite, on GitHub Pages). A "readiness check" fetches an OpenID Connect provider's discovery document and JWKS from the browser and reports whether its token-signing keys are quantum-breakable. Below it: a nine-step login walkthrough, an attack on it, a token-size explainer and a migration exercise.
- **An OIDC provider** (`packages/provider`, on `node-oidc-provider`) that signs ID tokens with ES256 or ML-DSA-65 per client (RFC 9964), and **two demo relying parties** (`packages/rp`).
- **A shared toolkit** (`packages/token-kit`): JWT measurement, size projection, verification with an algorithm allowlist, readiness analysis.
- **Evidence and deployment**: 82 tests, a Python interop verifier, `npm run prove`, a Helm chart, CI that deploys to kind.

### 2. What is already technically good

- The provider is real: authorization code + PKCE only, exact redirect URIs, per-client signing algorithm, ML-DSA-65 through Node's native crypto, verified independently in Python.
- Token verification is careful: algorithm allowlist, `alg: none` refused first, keys only from the JWKS, with tests for confusion and embedded keys.
- The walkthrough runs real primitives in the browser (ECDH, ML-KEM-768, AES-GCM, ECDSA, ML-DSA), and the attack does real decryption and forgery with the "recovered" keys.
- The migration model is a pure, tested function with ordering constraints and parts the company cannot change.
- Honest scoping in the README, a threat model that links mitigations to tests, hardened containers.

### 3. What is superficial or fake

- **The "check" is not a scan.** It reads two public JSON documents. It observes nothing about TLS: not the version, not the key exchange, not the certificate. The site says so, but the product is called a readiness tool and half the cryptographic posture is invisible to it.
- **One verdict** ("Not quantum-ready") stands in for a layered answer, and it conflates "publishes RSA keys" with overall readiness.
- **The walkthrough is a step machine.** `useSequence` moves an index on a timer; objects appear in panels by state, with CSS transitions between two positions. It cannot be scrubbed, and an operation is never seen half done.
- **The handshake is a sketch**: one signing key plays both the TLS certificate key and the token-signing key, the "signature + public key" travels in the clear (in TLS 1.3 the certificate flight is encrypted), and the channel key is one HKDF call rather than the TLS key schedule.
- **Token check** decodes and projects sizes but never verifies a signature against the issuer's keys.

### 4. Biggest weaknesses

1. No backend, so no TLS or certificate observation, no jobs, no persistence, no users.
2. No way to detect hybrid key exchange, which is the one post-quantum change already deployed on the public web.
3. Animation architecture cannot support scrubbing.
4. TLS and application authentication are blurred in the walkthrough (shared key, no certificate, no CertificateVerify).
5. Nothing connects a result to the matching explanation beyond one link that switches a mode.
6. The migration exercise does not know about the scan and has no testing/rollout step.

### 5. Target architecture

```
Browser ── SPA (apps/web) ──────────────┐  static build also runs alone on GitHub Pages
                                        │  (learning + token analysis; scans show recorded samples)
              same origin: /api, /auth  ▼
        ┌──────────────────────────────────────────────┐
        │ api (services/api)                           │  no internet egress
        │  REST API, OIDC relying party (BFF), jobs,   │
        │  SQLite (node:sqlite), rate limits, metrics  │
        └───────▲───────────────────────────┬──────────┘
   claim/complete jobs (HTTP, bearer token) │ code exchange, JWKS
        ┌───────┴──────────┐        ┌───────▼──────────┐
        │ worker           │        │ provider         │  the project's own OIDC provider,
        │ (services/worker)│        │ (packages/       │  ES256 or ML-DSA-65 ID tokens
        │  runs scan-core  │        │  provider)       │
        └───────┬──────────┘        └──────────────────┘
                │ only component with internet egress (NetworkPolicy)
                ▼
          scan targets
```

- **`packages/scan-core`**: target policy and SSRF defences, a TLS handshake observer, certificate summaries, HTTP transport checks, OIDC metadata, and the assessment that turns observations into labelled findings.
- **`services/api`**: owns users, sessions, scans and the job queue. Never connects to a scan target.
- **`services/worker`**: claims jobs from the API over HTTP, runs `scan-core`, posts results. Holds no user data, no database and no session secrets. It parses hostile bytes, so it is the part to isolate.
- **`packages/token-kit`**: extended into an isomorphic token analyzer that verifies in the browser.
- **`apps/web`**: the product UI and the learning experience.

Why: browsers cannot observe TLS, so scanning needs a server. The server makes outbound connections to user-chosen hosts, so the part that does it is separated from the part that holds data, and the network layer enforces the same rule the code does. See ADR 0005, 0007, 0008.

### 6. How real scanning works, and what can be observed

Verified during Phase 0 on this machine (Node 25.9, bundled OpenSSL 3.5.5):

- Node's TLS client negotiates X25519MLKEM768 with real servers, but `getEphemeralKeyInfo()` returns `{}` for it. **The negotiated hybrid group is not observable through Node's API.**
- Node does not expose the peer's CertificateVerify signature scheme on the client side.
- A Node TLS server accepts hybrid-only groups and an ML-DSA-65 certificate built with a small DER encoder, so varied local test servers need no external tools.

Therefore the scanner sends its own ClientHello and reads the server's answer off the wire (ADR 0006):

| Observation | How | Limits |
|---|---|---|
| TLS version, cipher suite | ServerHello (plaintext) | |
| Key-exchange group, classical / hybrid / PQ | `key_share` in ServerHello or HelloRetryRequest | Only for groups the scanner offers |
| Which PQ/hybrid groups the server accepts | one ClientHello per group with no key share; a HelloRetryRequest means yes, an alert means no | |
| What a non-PQ client gets | a classical-only ClientHello | |
| Whether TLS 1.2 is still accepted, and its key exchange | a TLS 1.2 ClientHello; Certificate and ServerKeyExchange are plaintext | |
| Certificate chain as sent, key types, signature algorithms | TLS 1.3: complete the key exchange, decrypt the server flight | |
| CertificateVerify scheme, and that the server holds the key | verify the signature over the transcript | |
| Chain trust | Node/OpenSSL validation against its CA bundle | Trust-store specific |
| HTTPS redirect, HSTS, cookie flags | pinned HTTP GET, redirects followed manually | |
| OIDC metadata and JWKS key types | `/.well-known/openid-configuration`, then `jwks_uri` | Only if published |

**Cannot be observed from outside, and reported as such**: the token-signing algorithm when no OIDC metadata is published; anything behind the TLS terminator (service-to-service TLS, databases, HSMs, vendor APIs); how private keys are stored; client-side support across a user population; QUIC/HTTP3; whether recorded traffic is being harvested.

### 7. Authentication

**Superseded: there is none (ADR 0014).** The first version required sign-in through the project's own provider (ADR 0009). The owner tried it and rejected it: it added a redirect and an account to a tool whose point is "paste an address, get an answer", and with published demo passwords it identified nobody. Scans are now anonymous, limited per visitor and per target, and deleted after a day. The provider remains in the repository as the ML-DSA-signing identity provider (`npm run oidc`).

### 8. Where Kubernetes adds value

Two places, both tied to the threat model: a **NetworkPolicy** that gives internet egress to the worker only and blocks private and metadata ranges even if the application-level SSRF check has a bug; and **privilege separation** between the pod that parses hostile network input and the pod that holds sessions and the database. Also probes, resource limits, read-only root filesystems and a PersistentVolumeClaim for SQLite. Not added: ingress controller, service mesh, external queue, Postgres, a metrics stack (ADR 0013).

Constraint: this machine has no Docker, kind or Helm, and the owner does not want them installed. Images and cluster deployment are verified in CI only; CI cannot run until the branch is pushed, which this work does not do. Locally the chart is rendered and schema-checked with tools kept outside the repo.

### 9. Learning experience redesign

One persistent stage (browser, network, server, and an attacker recording the network), driven by a pure function `sceneAt(t)`. The visitor types a made-up login into the form on the stage and presses Log in; the cryptography runs on what they typed and the stage shows where it went. One control: play or pause, and a timeline to drag. Objects are created, travel, combine in operations and transform; an operation scrubbed to its midpoint is drawn half done. TLS and the application are separate layers with **separate server keys** (certificate key, token-signing key). The attacker joins the same stage as a tap on the wire, and the same timeline continues into the attack. Values come from real primitives run in the browser; the protocol is simplified and the quantum step is conceptual, and both are labelled. Scan findings deep-link to the landmark and mode that explain them. See ADR 0011.

### 10. Phases and definitions of done

1. **Scan core, safety.** Address classifier (IPv4, IPv6, mapped and embedded forms), target policy (scheme, port, lab-origin exceptions), resolve-once-and-pin. *Done when* bypass tests pass: decimal/hex/octal IPs, `localhost` variants, IPv4-mapped IPv6, NAT64/6to4, redirects to internal addresses, DNS rebinding.
2. **Real analysis.** TLS 1.3 observer with hybrid groups, TLS 1.2 parsing, certificate summary, pinned HTTP fetcher, OIDC metadata, assessment. *Done when* tests pass against local servers (classical-only, hybrid-only, pure ML-KEM, ML-DSA certificate, TLS 1.2-only, RSA key transport, expired/self-signed), the key schedule matches RFC 8448, and a handful of public sites scan correctly.
3. **Token analysis.** Decode, classify, verify against issuer keys in the browser; `alg: none`, HMAC and confusion handled; header key URLs never followed. *Done when* those cases are tested.
4. **Service.** API, SQLite, job leases, worker, OIDC sign-in, CSRF, per-user authorization, rate limits, structured logs, metrics. *Done when* an end-to-end test signs in, scans a local target and reads the result, and authorization tests show users cannot see each other's scans.
5. **Results UI.** Layered report (observed / inferred / could not determine), history, compare, token page, links into learning. *Done when* driven in a real browser with screenshots.
6. **Timeline.** `sceneAt(t)` engine, login score, attacker cases, scrubber, reduced motion, keyboard, mobile. *Done when* unit tests assert states at chosen times and screenshots at fixed playhead positions look right.
7. **Migration.** Component model with inventory, dependencies, hybrid, compatibility, testing, rollout, rollback, decommissioning; seeded from a scan. *Done when* the model is tested and the UI is driven end to end.
8. **Infrastructure.** Dockerfile, Compose, Helm with NetworkPolicy and PVC, CI. *Done when* the chart renders and validates locally and CI definitions cover build, tests, kind deployment and a NetworkPolicy check.
9. **Hardening.** Independent security review, accessibility, mobile, performance, dependency audit.
10. **Final review** against the brief's definition of done; `FINAL_REPORT.md`; README; screenshots.

## Decisions log

| # | Decision | ADR |
|---|---|---|
| 5 | Product shape: scanner backend + SPA, with a static mode | [0005](adr/0005-scanner-backend-and-static-mode.md) |
| 6 | Custom TLS handshake observer | [0006](adr/0006-tls-handshake-observer.md) |
| 7 | SSRF: resolve once, validate, pin; lab origins | [0007](adr/0007-ssrf-defence.md) |
| 8 | API/worker split, HTTP job pull, SQLite | [0008](adr/0008-api-worker-sqlite.md) |
| 9 | Sign-in through the project's own provider, BFF | [0009](adr/0009-authentication.md) |
| 10 | Tokens are analyzed in the browser | [0010](adr/0010-token-analysis-in-browser.md) |
| 11 | Timeline as a pure function of time | [0011](adr/0011-timeline-pure-function.md) |
| 12 | Finding kinds instead of a score | [0012](adr/0012-finding-kinds-no-score.md) |
| 13 | Technology deliberately not added | [0013](adr/0013-not-added.md) |
| 14 | No accounts: anonymous scans, limits, one-day retention; migration page cut | [0014](adr/0014-no-accounts.md) |
| 15 | Given a site, find its sign-in (its own link, then the usual addresses) and assess that | [0015](adr/0015-find-the-sign-in.md) |

## Open questions

None blocking. "Scanning requires sign-in" was an assumption made without the owner, and it was wrong (ADR 0014). Still assumed: one scan covers one origin; the public GitHub Pages build stays a static mode showing saved results.

## Verified vs. unverified

Filled in at the end of each phase.

### Phase 0

- **Verified**: the existing suite passes (82 tests); the site runs and was driven in headless Edge; Node 25.9 bundles OpenSSL 3.5.5 with ML-KEM and ML-DSA; hybrid group not observable through Node's TLS API (tested against a public site and local servers); local TLS servers with hybrid groups, TLS 1.2-only, RSA key transport and an ML-DSA-65 certificate work using only Node.
- **Unverified**: Docker build, Compose and the kind deployment (no Docker on this machine).

### Phases 1 and 2 (scan core)

- **Verified by tests** (`packages/scan-core`, 265 tests):
  - Address classification for every blocked IPv4/IPv6 range, including IPv4-mapped, NAT64 and 6to4 forms; numeric host forms; `localhost` variants; mixed DNS answers; a rebinding resolver (one lookup, every socket to the pinned address).
  - The TLS 1.3 key schedule reproduces every intermediate value of the RFC 8448 trace; the observer replays that trace, decrypts the flight and verifies CertificateVerify and Finished.
  - Complete handshakes against OpenSSL 3.5.5 servers in X25519, P-256, P-384, X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM768 and MLKEM1024 (Finished verifies, so both sides derived the same secret); ECDSA, RSA-PSS and ML-DSA-65 CertificateVerify; TLS 1.2 ECDHE and RSA key transport; group enumeration by HelloRetryRequest.
  - Whole scans of seven lab configurations give the expected findings; redirects to metadata, loopback, internal names, other ports and schemes are reported and not followed; an internal `jwks_uri` is not fetched; size cap, timeout and deadline hold.
- **Verified by running against public sites** (2026-10-02, four sites, one scan each plus one repeat): accounts.google.com (X25519MLKEM768 negotiated, MLKEM1024 also accepted, Finished verified against BoringSSL), www.cloudflare.com (X25519MLKEM768), login.microsoftonline.com (secp384r1 after a HelloRetryRequest, RSA certificate, resets instead of alerting on unknown groups), github.com (x25519, AES-128-GCM, no OIDC metadata).
- **Not verified / limits**: QUIC; servers behind client-certificate requirements; groups outside the registry; behaviour through an HTTP proxy (the scanner connects directly); IPv6 targets (code path tested with literals, not with a live IPv6 server).
- **Found and fixed along the way**: PEM encoder emitted a blank line at exact multiples of 64 characters; a reset in reply to a group-only ClientHello is now reported as a refusal rather than "unknown".

### Phase 3 (token analysis)

- **Verified by tests** (`packages/token-kit`, 63 tests): genuine RS256, PS256, ES256, ES384, EdDSA and ML-DSA-65 tokens verify; edited payloads and foreign keys do not; `alg: none` in four capitalisations is unsigned, never valid; an HS256 token "signed" with the RSA public key is never checked against published keys; a key is not used for an algorithm it was not published for; embedded `jwk` is ignored; `jku`/`x5u` are flagged and no network request is made; JWE is recognised and not "read".
- **Verified in a real browser**: the signed-in user's own ML-DSA-65 ID token verifies in the page against the provider's keys.

### Phase 4 (service)

- **Verified by tests** (`tests/service.test.ts`, 62 tests, real provider + API + worker + lab server in one process): sign-in end to end; replayed, stolen and state-tampered callbacks; open-redirect attempts; logout; session expiry; every API route refuses without a session; cross-user read, list and delete; CSRF (missing or foreign token, foreign Origin, cross-site fetch metadata, form body); target refusals before queuing; per-user, active and per-host limits; worker token and port separation; lease expiry, retry once, then `worker-lost`; a full scan of a lab server through the worker; no credential in the logs. Mutation check: removing the owner filter or the CSRF check makes tests fail.
- **Not verified**: more than one API replica (not supported: SQLite); behaviour behind a real reverse proxy; load.

### Phases 5 and 6 (web app)

- **Verified in headless Edge** (scripts and screenshots in the untracked `.shots/`): sign in, scan a lab server, report renders; recorded reports; token examples; own-token verification; the stage at fixed playhead positions in all three modes with and without an attacker; phone viewport (390 px) with no horizontal overflow on any page; no console errors under the Content-Security-Policy after fonts were made same-origin.
- **Verified by tests** (`apps/web/src/learn/learn.test.ts`, 38 tests): the nine mode/attacker scores validate; `sceneAt` is order-independent; a share is mid-network at mid-trip; a signature is half formed at the midpoint of signing; the login is scrambled only between encrypt and decrypt; no prop jumps between frames; the six attack outcomes are real decryptions and verifications.
- **Not yet checked**: history and compare views in a browser; autoplay with motion enabled; keyboard control of the playhead in a browser; screen-reader behaviour; Firefox and Safari.
- **Known gaps**: `README.md` still describes the old site; nothing in `deploy/`, `Dockerfile`, `docker-compose.yml` or `.github/` has been updated for the new services yet.

### The rework (no accounts, verdict first, a login you do)

The Phase 4 to 6 notes above describe the first version; sign-in, history, compare and CSRF-token tests no longer exist.

- **Verified by tests** (467 in all, `npm test`):
  - `tests/service.test.ts` (45, API + worker + lab servers in one process): a scan needs no cookie and is read by its ID; cross-site and non-JSON posts are refused; target refusals before queuing; per-visitor, in-progress and per-service limits, the last one keyed on normalised name and port; a repeat within the window returns the earlier scan and a failed one is not reused; only a keyed hash of the address is stored; results are deleted after the retention period; worker token, port separation, leases and retry; no token or address in the logs.
  - `packages/scan-core/src/summary.test.ts` (15): the verdict and the three answers for each lab configuration; an unreachable target is "could not tell", never "safe".
  - `apps/web/src/learn/learn.test.ts` (42): as before, plus: a typed login is what is encrypted, sent and decrypted; a quantum attacker's own decryption gives it back on a classical site; on a hybrid site nothing she holds contains it; a watched-only score shares every beat of the login with an attack score.
- **Verified in headless Edge** (`.shots/v2-*.mjs`): scan a lab server from the home page with one press and read the verdict (classical: not quantum-safe; hybrid: partly; post-quantum: quantum-safe; expired certificate listed under "also noticed"); saved results; token examples; typing a login, pressing Log in, the typed password in the login chip and, after "give her a quantum computer" on the classical site, in the attacker's panel; a link from a result landing on a moment and playing; phone width. No console errors. Frame times while playing: 990 frames in 6 s, median 6.1 ms, worst 7.7 ms.
- **Not verified**: how the explainer feels to a person at the chosen pace; Firefox and Safari (the stage relies on CSS `zoom`, standard and shipping in all three, tested only in Edge); screen readers; the service behind a real proxy.
