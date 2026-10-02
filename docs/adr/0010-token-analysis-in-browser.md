# 10. Tokens are analyzed in the browser; the server never receives them

**Status:** accepted · 2026-10-02

## Context

People will paste real tokens. A token is a credential until it expires.

## Decision

- Decoding, classification and signature verification run in the browser (`token-kit`, Web Crypto, `@noble/post-quantum` for ML-DSA). The token is not sent to the API, not stored, not logged.
- To verify a signature the page needs the issuer's public keys. It fetches the discovery document and JWKS directly, after the user confirms the host. Only `https:` issuers are fetched, and never an IP-literal host.
- If the issuer blocks cross-origin requests, the user can ask the scanner to fetch the same two public documents through the SSRF-safe path. Only the issuer URL is sent.
- Header parameters that point at keys (`jku`, `x5u`, `jwk`, `x5c`) are displayed and flagged, never fetched or trusted.
- `alg: none` is reported as unsigned. HMAC algorithms are reported as not verifiable without the shared secret, and a public key is never tried as an HMAC secret.

## Alternatives

- **`POST /tokens/analyze`.** Simpler to build. It moves a credential across the network to a service that then has to promise not to log it.

## Consequences

- Verification proves "signed by a key published at this issuer URL". It does not prove the issuer should be trusted, and the report says so.
- The command-line check does the same work locally.
