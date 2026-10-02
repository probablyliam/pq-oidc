# 13. Technology deliberately not added

**Status:** accepted · 2026-10-02

Each of these was considered and left out because it would not solve a problem this project has.

| Not added | Why |
|---|---|
| **Keycloak** | The project already contains a provider built on an OpenID Certified library, and it can sign with ML-DSA. See ADR 0009. |
| **Postgres** | One API replica and one writer; SQLite is enough and can be verified on a machine without containers. See ADR 0008. |
| **Redis / a message broker** | The scans table is the queue. Leases and retries are a few SQL statements. |
| **An ingress controller** | The API serves the built site on the same origin. Port-forwarding is enough for a local cluster. |
| **A service mesh / mTLS between pods** | Three services, one shared-secret link. NetworkPolicy gives the isolation that matters here. |
| **Prometheus, Grafana, OpenTelemetry collectors** | The API exposes `/metrics` in the Prometheus text format and logs JSON with request and scan IDs. Running a metrics stack is the operator's choice. |
| **A web framework (Express, Fastify)** | The existing services use `node:http` directly; a small router keeps the dependency surface and the request path short enough to read. |
| **An animation library (GSAP)** | See ADR 0011. |
| **A second TLS stack (oqs-provider, BoringSSL bindings)** | Node 25 ships OpenSSL 3.5 with ML-KEM and ML-DSA; the observer needs primitives, not another handshake implementation. See ADR 0006. |
| **A PQ certificate authority for public trust** | None is trusted by browsers yet. The lab uses self-signed ML-DSA certificates and says so. |
| **TLS 1.0/1.1, cipher-by-cipher enumeration, vulnerability probes (Heartbleed, ROBOT…)** | General TLS hygiene, well served by existing tools, and not what this scanner is for. |
