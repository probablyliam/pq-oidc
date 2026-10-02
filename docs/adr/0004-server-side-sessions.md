# 4. Keep tokens server-side; cookies hold only a session ID

**Status:** accepted · 2026-09-30

## Context

Many web apps store the ID token in a cookie. An ML-DSA-65 ID token for an ordinary user is about 4.9 KB, and browsers silently refuse cookies over 4,096 bytes. The login appears to work, then the next request arrives without the cookie and the user is signed out, with no error anywhere.

Options:

1. **Split the token across several cookies** (ASP.NET Core does this automatically). Works, but every request carries ~5 KB of cookies, and the per-domain cookie budget runs out quickly.
2. **Put fewer claims in the ID token.** Helps a little; the signature alone is 4.4 KB once encoded.
3. **Keep the token on the server** and give the browser a random session ID.

## Decision

Option 3. The demo apps store the verified token and claims in a server-side session and set a 32-character, `HttpOnly`, `SameSite=Lax` session cookie.

To make the problem visible, the PQ-Ready App also tries the naive approach on every sign-in and reports whether the browser kept the cookie. It never does.

## Consequences

- Cookie size no longer depends on the signature algorithm.
- Sessions need server-side storage. The demo keeps them in memory (single replica); production would use a shared store.
- The migration simulator treats "token stored in a cookie" as a blocker that has to be fixed before an app can move to ML-DSA.
