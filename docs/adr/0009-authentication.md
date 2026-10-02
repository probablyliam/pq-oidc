# 9. Sign-in through the project's own OIDC provider, with the API as a backend-for-frontend

**Status:** accepted · 2026-10-02

## Context

The scanner acts on a user's behalf against third-party hosts. It needs to know who asked, to limit how much each person can ask, and to keep each person's history private.

## Decision

- **Scanning requires sign-in.** Learning pages and token analysis do not.
- **The API is the OIDC client**, using `openid-client`: Authorization Code with PKCE (S256), `state`, `nonce`, a confidential client secret. The ID token signature is then checked explicitly against an algorithm allowlist with `token-kit`.
- **The browser holds only a session cookie** (`HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS). Tokens stay on the server. The database stores a hash of the session ID.
- **CSRF**: state-changing requests need a per-session token in a header and must be same-origin.
- **Authorization**: every scan row has an owner; every query filters by it. Another user's scan ID returns 404.
- **The identity provider is `packages/provider`**, registered as a third client (`scanner-web`) whose ID tokens are signed with ML-DSA-65 by default. Any OIDC issuer can be used by changing `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`.
- **Logout** ends the local session and sends the browser to the provider's `end_session_endpoint`.

## Alternatives

- **Keycloak.** A good general choice and the brief's suggestion. Here it would add a Java service that cannot run on this machine (no Docker) to replace a certified-library provider the project already has, and it does not sign with ML-DSA. The API stays compatible with it.
- **Tokens in the browser (public client).** Puts tokens within reach of any script on the page. The backend-for-frontend pattern is the current recommendation for browser apps.
- **No authentication.** An open scanner with no accountability.

## Consequences

- The demo users have a published password. That is a property of the bundled provider, documented in the threat model.
- The signed-in user can analyze the ID token from their own sign-in, which connects the tool to the token and learning views.
