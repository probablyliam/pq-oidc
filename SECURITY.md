# Security policy

pq-oidc is a portfolio project: a scanner you run yourself, and a demonstration identity provider. See the [threat model](docs/threat-model.md) for what it does and doesn't protect against.

If you find a vulnerability in the code (for example a way to make the scanner connect to a private address, a way past the token verifier, or a hole in the API's limits), please report it privately through [GitHub security advisories](https://github.com/probablyliam/pq-oidc/security/advisories/new) rather than a public issue.

The token checker never sends pasted tokens anywhere, and the scanner sends a pasted address only to the scan service you are running. If you find a case where it does, that is a security bug; please report it the same way.
