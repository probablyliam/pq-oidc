# 14. No accounts: scans are anonymous, limited per visitor, and kept for a day

**Status:** accepted · 2026-10-02 · supersedes [0009](0009-authentication.md)

## Context

The first version made visitors sign in before scanning, through the project's own OIDC provider, and kept each user's scan history. The owner's review of it, in their words: "having to ACTUALLY login to the page defeats the purpose of the tool", "why are we saving scans and making a real user?", and the intended shape is "a vibe similar to virus total maybe where you can scan something and it will tell you if the login is quantum safe or not".

They are right about the product. The demo accounts had a published password, so sign-in identified nobody: it added a redirect, a session store, CSRF tokens and a second service to run, and bought no accountability. What the scanner needs from an identity is only a way to stop one visitor using it to hammer a third party.

## Decision

- **No sign-in, no users, no sessions, no cookies.** Paste an address, get a result.
- **A scan's ID is its only key.** It is a random UUID (122 bits); whoever has the link can read the result. Nothing lists scans.
- **Results are kept for 24 hours** (`RETENTION_HOURS`), then deleted by a sweeper. There is no history to browse and no compare view.
- **Limits take the place of accountability**, all enforced before a job is queued:
  - per visitor: 20 scans per 10 minutes and 3 in progress (`RATE_LIMIT_SCANS`, `MAX_ACTIVE_SCANS_PER_CLIENT`);
  - per target service (name and port), whoever asks: 3 per minute (`RATE_LIMIT_PER_HOST`), so the scanner cannot be pointed at one site from many visitors;
  - a repeat of the same target within 5 minutes is answered with the earlier scan instead of a new one (`REUSE_RESULT_SECONDS`);
  - a queue ceiling (`MAX_QUEUE_DEPTH`).
- **A visitor is a keyed hash of their address.** The database stores `HMAC(key, address)` with a key made at start-up and never written down, so stored rows cannot be turned back into addresses and do not link across restarts. The address itself is not stored or logged. `X-Forwarded-For` is believed only when the service is told it is behind a proxy.
- **Cross-site requests are refused.** With no cookie there is nothing to forge, but a page elsewhere could still spend a visitor's allowance or use them as a relay: `POST /api/v1/scans` requires a JSON body and, when the browser sends them, a same-origin `Origin` and `Sec-Fetch-Site`.
- **The SSRF defence is unchanged** (ADR 0007). It never depended on who was asking.
- **The OIDC provider stays in the repository** as the ML-DSA-signing identity provider the project started as (`npm run oidc`), and as a scan target. The scanner no longer depends on it.
- **The migration exercise is cut.** The owner: "maybe we don't even need the migrate page this is already getting too complicated". Its model and tests remain in the history (commit `411c1d6`).

## Alternatives

- **Keep sign-in, make it optional.** Two code paths and the same confusing page for a feature (history) nobody asked for.
- **A CAPTCHA.** A third-party script and a worse first impression, to solve a problem rate limits already bound.
- **API keys.** Right for a public service with real users. This is a tool someone runs themselves.

## Consequences

- Anyone who can reach the service can scan, within the limits. A deployment on the public internet should sit behind a proxy that sets the client address, and should expect the per-visitor limit to be only as good as that address.
- Visitors behind one NAT share an allowance.
- A result link is a bearer secret for a day. Reports contain only what the scanned server shows to everyone, so the exposure is small.
- Much less code: `services/api/src/auth.ts`, the session and user tables, the CSRF token, and the history and compare views are gone.
