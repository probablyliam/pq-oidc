# Security policy

pq-oidc is a demonstration and portfolio project, not a production identity provider. See the [threat model](docs/threat-model.md) for what it does and doesn't protect against.

If you find a vulnerability in the code (for example a way past the token verifier, the PKCE checks, or the login page's protections), please report it privately through [GitHub security advisories](https://github.com/probablyliam/pq-oidc/security/advisories/new) rather than a public issue.

The Token Lab never sends pasted tokens anywhere. If you find a case where it does, that is a security bug; please report it the same way.
