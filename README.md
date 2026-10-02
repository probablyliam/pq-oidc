# Could a quantum computer log in as you?

[![CI](https://github.com/probablyliam/pq-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/probablyliam/pq-oidc/actions/workflows/ci.yml)
[![CodeQL](https://github.com/probablyliam/pq-oidc/actions/workflows/codeql.yml/badge.svg)](https://github.com/probablyliam/pq-oidc/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**pq-oidc** answers that question for any login service, shows how the forgery would work, and is a working login service that makes the fix: it moves apps to quantum-proof signatures one at a time.

### ▶ [Try it: probablyliam.github.io/pq-oidc](https://probablyliam.github.io/pq-oidc/)

<p align="center"><img src="docs/media/site-question.png" width="720" alt="The site asks 'Could a quantum computer log in as you?' and answers 'Yes.' for Google, because Google signs logins with RSA keys."></p>

## The idea in five sentences

1. When you sign in with Google or a work account, a login service gives the app a short signed message, a **token**, saying who you are.
2. The app trusts the token because of its **signature**, which today is made with RSA or elliptic-curve keys.
3. A large enough quantum computer could work out those secret keys from the public ones, and then sign in as anyone.
4. A replacement signature exists (**ML-DSA**, standardised in 2024), but it is about fifty times longer, which breaks things: the token no longer fits in a browser cookie, and apps must be updated before they can read it.
5. So the switch has to happen one app at a time, and this project is a login service that does exactly that.

The [site](https://probablyliam.github.io/pq-oidc/) walks through those five steps. You do each one yourself, with real signatures computed in your browser.

<table>
<tr>
<td width="50%"><img src="docs/media/site-forged.png" alt="A forged login token, stamped FORGED, is accepted by the app once the attacker has a quantum computer."></td>
<td width="50%"><img src="docs/media/site-fix.png" alt="With the new signature the same forged token is rejected."></td>
</tr>
<tr>
<td><b>Old signature.</b> With a quantum computer, the forged token is accepted.</td>
<td><b>New signature.</b> The same attack is rejected.</td>
</tr>
<tr>
<td width="50%"><img src="docs/media/site-cost.png" alt="One square per byte: the token with the new signature is 4,844 bytes, 757 more than a cookie holds."></td>
<td width="50%"><img src="docs/media/site-switch.png" alt="A migration board: the login service holds both keys while four apps move to the new signature one at a time."></td>
</tr>
<tr>
<td><b>The catch.</b> One square per byte. The new token doesn’t fit in a cookie.</td>
<td><b>The switch.</b> One app at a time, or people get locked out.</td>
</tr>
</table>

## Check your own login service

The check reads the public keys a login service publishes (every OpenID Connect provider publishes them) and reports whether they could be broken by a quantum computer.

- **In the browser:** pick "Your company’s…" on the [site](https://probablyliam.github.io/pq-oidc/) and paste the address, for example `https://your-company.okta.com`. Your browser fetches the keys directly; nothing passes through this project.
- **From a terminal** (works for services that block browsers, and for ones only reachable inside your network):

```bash
npm run check -- https://your-company.okta.com
```

On 2026-10-02 it reported **not ready** for all 20 public login services I tried, including Google, Microsoft, Apple, Okta, Auth0, Salesforce, Atlassian, Slack, PayPal, GitLab and Red Hat’s Keycloak.

**What it can and can’t tell you.** It reads what the service publishes: the algorithms it offers and the keys it signs with. It can’t see services that don’t speak OpenID Connect, and it doesn’t test your apps, only the login service they rely on.

## How do you know it works?

```bash
npm run prove
```

That one command starts the real login service, performs real sign-ins, and checks every claim with code that shares nothing with the code under test:

```
1. Real sign-ins against the provider
   legacy-app received a 498-byte ID token, pq-app a 4824-byte ID token
2. The provider's published keys, read with plain fetch (no project code)
   EC/ES256, AKP/ML-DSA-65
3. Independent verification in Python
   ✓ Python accepts the ES256 token
   ✓ Python accepts the ML-DSA-65 token (3,309-byte signature per FIPS 204)
4. A legacy configuration refuses the post-quantum token
   ✓ REJECTED alg-not-allowed
   ✓ REJECTED bad-signature (corrupted token)
5. Readiness verdicts next to the raw key types
   ✓ this provider (EC + AKP keys): partial
   ✓ Google (RSA/RS256, RSA/RS256): not-ready
All claims held.
```

Beyond that:

- **Two independent verifiers.** The TypeScript verifier and a separate [Python verifier](interop/python) (built on `pyca/cryptography`) must agree on every honest token and reject six kinds of forgery with identical codes (`npm run interop`).
- **A real browser.** Chrome silently dropped the 4,895-byte cookie holding the new token; the end-to-end tests reproduce that behaviour.
- **A real cluster.** CI deploys the service to Kubernetes, signs in through both apps, then switches an unprepared app too early and expects its sign-in to fail.
- **69 automated tests**, including the classic token attacks and protocol abuse (see [Security](#security)).

## Has this been done before?

Partly, and it’s worth being exact about it.

- **The size problem is known.** The [OpenID Foundation described it](https://openid.net/post-quantum-openid-connect/) in September 2026, as did others. This project measures it; it didn’t discover it.
- **Post-quantum token libraries exist** in several languages, and some identity servers have started adding ML-DSA.
- **What I couldn’t find elsewhere:** a tool that checks whether an arbitrary login service is quantum-ready, an exact byte-for-byte projection for your own tokens, and a runnable login service that demonstrates the per-app switch along with its failure modes.

## Run the login service

Needs Node.js 24.7 or newer (for native ML-DSA). Dependencies install into the project folder only.

```bash
git clone https://github.com/probablyliam/pq-oidc.git
cd pq-oidc
npm install
npm start
```

| | Address | Signature it receives |
|---|---|---|
| Legacy App | http://localhost:3001 | old (ES256) |
| PQ-Ready App | http://localhost:3002 | new (ML-DSA-65) |
| Login service | http://localhost:3000 | |

Sign in as `alice` or `bob`, password `quantum-safe` (fictional demo users).

<p align="center"><img src="docs/media/pq-app-signed-in.png" width="440" alt="PQ-Ready App after sign-in: a 4,879-byte token with the new signature; the browser silently dropped the 4,895-byte cookie."></p>

```bash
# Switch Legacy App to the new signature before it's ready, and watch sign-in fail with a clear reason
LEGACY_ID_TOKEN_ALG=ML-DSA-65 npm start

# What happens to one of your own tokens
npm run check -- eyJhbGciOi...
```

**Docker:** `docker compose up --build`. **Kubernetes:** a Helm chart is in [`deploy/helm/pq-oidc`](deploy/helm/pq-oidc).

---

# For engineers

## Measurements

Measured on the running system. Method and details: [docs/findings.md](docs/findings.md).

| | ES256 | ML-DSA-65 | |
|---|---:|---:|---|
| Signature | 64 B | 3,309 B | fixed by FIPS 204 |
| ID token for a typical user | 553 B | 4,879 B | 8.8× |
| Public key in the JWKS | 204 B | 2,707 B | 13× |
| Sign / verify (Node.js, native) | 0.08 / 0.10 ms | 0.55 / 0.14 ms | speed isn’t the problem |

## Architecture

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant A as App (relying party)
  participant P as pq-oidc provider
  B->>A: GET /login
  A->>B: redirect to /auth (PKCE S256, state, nonce)
  B->>P: sign in (alice / password)
  P->>B: redirect to /callback?code=…
  B->>A: GET /callback?code=…
  A->>P: POST /token (code + client secret + PKCE verifier)
  P-->>A: ID token signed with this client's algorithm (ES256 or ML-DSA-65)
  A->>P: GET /jwks (EC key + AKP key, cached)
  A->>A: verify signature against allowlist, iss, aud, nonce, exp
  A->>B: session cookie (a random ID, not the token)
```

- **Provider** ([`packages/provider`](packages/provider)): [`oidc-provider`](https://github.com/panva/node-oidc-provider) (OpenID Certified), configured as an OAuth 2.1-style server: authorization code flow only, PKCE S256 required, exact redirect URIs, single-use codes. It publishes an ES256 key and an ML-DSA-65 key (RFC 9964 `"kty": "AKP"`). Each client's `id_token_signed_response_alg` decides which one signs its tokens; that setting is the migration switch.
- **Apps** ([`packages/rp`](packages/rp)): `openid-client` runs the protocol. The ID token signature is then verified explicitly with an algorithm allowlist, which is what makes an unprepared app refuse ML-DSA and what stops `alg: none` and algorithm confusion.
- **Shared toolkit** ([`packages/token-kit`](packages/token-kit)): measurement, exact size projection, verification, and the readiness analysis used by the CLI and the site.
- **Python verifier** ([`interop/python`](interop/python)): about 150 lines, because no Python JWT library supports RFC 9964 yet.
- **Site** ([`apps/lab`](apps/lab)): static React. ML-DSA runs in the browser through `@noble/post-quantum`; tests prove its tokens interoperate with Node's native ML-DSA both ways.

No build step for the server code: Node.js 24 runs the TypeScript sources directly.

## Security

The [threat model](docs/threat-model.md) covers the provider, apps and tokens with STRIDE, linking each mitigation to the test that proves it. Tests include:

- **Token forgery:** `alg: none`, algorithm confusion (HS256 signed with the public key), attacker keys embedded in the header, edited claims, expired tokens, wrong audience, nonce replay.
- **Protocol abuse:** missing PKCE, `plain` PKCE, implicit flow, unregistered redirect URIs, unknown clients, authorization code replay, stolen codes without the verifier, one app redeeming another's code, wrong client secret.
- **Web:** CSP without `unsafe-inline`, `frame-ancestors 'none'`, HTML escaping, login CSRF across browser sessions, no private key material in the JWKS.
- **Containers:** non-root, read-only filesystem, all capabilities dropped, seccomp `RuntimeDefault`.

CI also runs CodeQL, `npm audit`, and Dependabot.

**Not production-ready by design:** state and keys live in memory (one replica), there's no rate limiting on the login form, and demo users have a published password. See [residual risks](docs/threat-model.md#residual-risks-and-deliberate-non-goals).

## Design decisions

1. [Build on node-oidc-provider instead of writing an OIDC server](docs/decisions/0001-use-node-oidc-provider.md)
2. [Use ML-DSA-65 (and why not SLH-DSA, FN-DSA or composite signatures yet)](docs/decisions/0002-ml-dsa-65.md)
3. [Migrate one app at a time with per-client signing algorithms](docs/decisions/0003-per-client-algorithm.md)
4. [Keep tokens server-side; cookies hold only a session ID](docs/decisions/0004-server-side-sessions.md)

## Development

```bash
npm test            # 69 tests
npm run lint && npm run typecheck
npm run prove       # the evidence above (needs the Python venv)
npm run interop     # Python <-> Node, both directions
npm run lab:dev     # the site, locally

# one-time Python setup (3.10+), inside the project folder
python -m venv interop/python/.venv
interop/python/.venv/bin/pip install -r interop/python/requirements.txt   # Windows: .venv\Scripts\pip
```

## Standards

[RFC 9964: ML-DSA for JOSE and COSE](https://www.rfc-editor.org/info/rfc9964/) · [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) · [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) · [OAuth 2.1 (draft)](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) · [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636) · [RFC 6265: Cookies](https://www.rfc-editor.org/rfc/rfc6265)

## License

[MIT](LICENSE)
