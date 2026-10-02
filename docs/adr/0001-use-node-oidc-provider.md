# 1. Build on node-oidc-provider instead of writing an OIDC server

**Status:** accepted · 2026-09-30

## Context

The interesting part of this project is the signature migration, not the OAuth protocol. But the protocol is where security bugs live: redirect URI matching, code replay, PKCE, session handling, error responses that leak or redirect where they shouldn't. Writing it from scratch would make most of the codebase protocol plumbing, and most of the risk.

## Decision

Use [`oidc-provider`](https://github.com/panva/node-oidc-provider) (v9), which is OpenID Certified™ and maintained by the author of `jose` and `openid-client`. Since Node.js 24.7 it signs ID tokens with `ML-DSA-44/65/87`, using the RFC 9964 identifiers. Our code configures it (`config.ts`) and adds only the login UI and the per-client algorithm policy.

The demo apps use `openid-client` for the protocol, plus our own `verifyIdToken` for the signature check (see ADR 3).

## Consequences

- The security-critical protocol code is certified and widely deployed; our tests check that our **configuration** is strict (PKCE required, code flow only, exact redirect URIs).
- The library defaults to an in-memory store. That's acceptable for a single-replica demo and documented as a residual risk; production would plug in its adapter interface (Redis, a database).
- We depend on Node.js ≥ 24.7 for native ML-DSA, which the Dockerfile and CI pin.
