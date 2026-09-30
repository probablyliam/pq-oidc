# 3. Migrate one app at a time with per-client signing algorithms

**Status:** accepted · 2026-09-30

## Context

A provider serves many apps, and they can't all upgrade at once. An app whose JWT library doesn't know ML-DSA rejects every ML-DSA token, so a big-bang switch logs everyone out of every unprepared app. Options considered:

1. **Switch everything at once.** Simple, and guaranteed to break some apps.
2. **Stand up a second, post-quantum issuer.** Clean separation, but every app must be re-registered, users see a new login, and sessions don't carry over.
3. **Sign every token twice** (JWS JSON serialization with two signatures). Standard, but ID tokens must be compact JWS, and it doubles the size problem.
4. **Per-client algorithm.** OIDC already lets each registered client declare `id_token_signed_response_alg`. Publish both keys in one JWKS and change the setting app by app.

## Decision

Option 4. The provider publishes an ES256 key and an ML-DSA-65 key side by side. Each client's registration names the algorithm it receives (`LEGACY_ID_TOKEN_ALG`, `PQ_ID_TOKEN_ALG`, or `apps.<name>.idTokenAlg` in Helm). Apps verify with an explicit allowlist, which is what the migration changes.

The safe order is: publish the new key → upgrade an app's library and move tokens out of cookies → switch that app → repeat → retire the classical key.

We also verify ID token signatures in the apps even though OIDC Core §3.1.3.7 allows skipping it for tokens received directly from the token endpoint over TLS (which `openid-client` does by default). The allowlist check is the point of the migration, and doing it explicitly makes an unprepared app fail loudly instead of silently trusting whatever arrives.

## Consequences

- No flag day and no new issuer; rollback for any app is one setting.
- The provider holds two private keys during the migration, so both need protecting.
- Tested at three levels: unit (allowlist), end-to-end (Legacy App rejects ML-DSA-65 with a clear error), and in Kubernetes (CI upgrades the Helm release to migrate Legacy App too early and expects the sign-in to fail).
