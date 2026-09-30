# Findings

Measurements from the running system (`npm start`, Node.js with native ML-DSA), signing a realistic ID token for the demo user Alice (`sub`, `name`, `given_name`, `family_name`, `email`, `email_verified`, `nonce`, plus the standard `iss`, `aud`, `iat`, `exp`, `auth_time`).

## 1. The ID token grows 8.8×

| | ES256 | ML-DSA-65 | Change |
|---|---:|---:|---:|
| Signature (raw) | 64 B | 3,309 B | 52× |
| Whole ID token | 553 B | 4,879 B | 8.8× |
| Public key in the JWKS | 204 B | 2,707 B | 13× |

The claims didn't change. The difference is almost entirely the signature, which FIPS 204 fixes at 3,309 bytes for ML-DSA-65.

## 2. The token no longer fits in a cookie

Browsers reject cookies whose name and value exceed 4,096 bytes ([RFC 6265 §6.1](https://www.rfc-editor.org/rfc/rfc6265#section-6.1) sets 4,096 as the minimum they must support, and major browsers use it as the maximum). They do it **silently**: no error, the cookie just isn't stored.

The PQ-Ready App deliberately tries the naive approach on every sign-in and reports what the browser did:

- Legacy App (ES256): a 571-byte cookie, kept.
- PQ-Ready App (ML-DSA-65): a 4,895-byte cookie, **dropped**. Confirmed in Chrome; the end-to-end tests reproduce the browser's behaviour.

An app that stores the ID token in a cookie would appear to log in successfully and then log the user straight back out.

**Fix used here:** keep the token server-side and put a 32-character session ID in the cookie ([ADR 0004](decisions/0004-server-side-sessions.md)).

**Knock-on effects to check in a real migration:**

- Reverse proxies and load balancers cap request header size (commonly 8 KB per header line or 16 KB in total). A PQ token sent as a bearer header uses a large share of that.
- Anything that logs tokens will log about nine times more data.
- JWKS responses grow (2.9 KB here for two keys), which matters for clients that fetch them often.

## 3. Signing and verification speed is not the problem

Measured with `jose` on Node.js (native ML-DSA), averaged over 200 runs on a laptop:

| | ES256 | ML-DSA-65 |
|---|---:|---:|
| Sign a JWT | 0.08 ms | 0.55 ms |
| Verify a JWT | 0.10 ms | 0.14 ms |

Verification, which every app does on every sign-in, is nearly as fast. Signing is slower but still well under a millisecond. Even the pure-JavaScript ML-DSA in the Token Lab signs in a few milliseconds. The cost of the migration is bytes, not CPU.

## 4. Major identity providers aren't ready yet

The Token Lab's provider check and `npm run check` read live metadata. On 2026-09-30, Google, Microsoft Entra ID, Apple, GitLab, Auth0's demo tenant and GitHub Actions' OIDC issuer offered only classical ID token algorithms (RS256 everywhere; Auth0 also lists PS256 and HS256), and none published an ML-DSA key. Snapshots of three of them are kept as test fixtures in `packages/token-kit/src/fixtures/`.

## 5. Migration order matters

The end-to-end tests and the CI Kubernetes job both demonstrate the failure you avoid with a per-client rollout: switching Legacy App to ML-DSA-65 before its library supports it makes every sign-in fail with *"The token is signed with ML-DSA-65, but this app only accepts ES256."* The safe order is:

1. Publish the ML-DSA-65 key next to the ES256 key. Nothing changes for apps.
2. For each app: upgrade its OIDC library, move tokens out of cookies, then switch its algorithm. ES256 remains the rollback.
3. Retire the ES256 key once no app uses it.
