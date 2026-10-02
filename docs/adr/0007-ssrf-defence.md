# 7. SSRF defence: resolve once, validate, pin

**Status:** accepted · 2026-10-02

## Context

The scanner connects to hosts chosen by users. Without controls it is a tool for reaching cloud metadata services, cluster-internal services and anything on the operator's network.

## Decision

Every outbound connection goes through one path in `scan-core/net`:

1. **Parse** with the WHATWG URL parser, which canonicalises numeric host forms (`2130706433`, `0x7f.1`, `0177.0.0.1`) to dotted decimal. Only `https:` targets; only ports on an allowlist (443, 8443). Credentials in the URL are rejected.
2. **Resolve once.** Every returned address is classified. If any is non-public the target is refused, so a name that answers with a mix of public and private addresses cannot be used.
3. **Classify** with an explicit table of IPv4 and IPv6 ranges: loopback, private, link-local (which contains the metadata addresses), CGNAT, multicast, reserved, documentation, unique-local. IPv4-mapped, IPv4-compatible, NAT64 and 6to4 addresses have the embedded IPv4 address extracted and checked.
4. **Pin.** Sockets are opened to the validated IP. The hostname is used only for SNI and the Host header. Nothing resolves the name a second time, which is what defeats DNS rebinding.
5. **Redirects** are never followed by the HTTP client. Each `Location` goes back to step 1, with a cap of five hops.
6. **Limits**: connect, handshake and read timeouts; a response size cap; an overall deadline per scan.
7. **Rate limits** in the API: per user, per target host, and a queue cap.
8. **Network layer**: in Kubernetes only the worker has internet egress, and its NetworkPolicy excludes private and link-local ranges. A bug in steps 1–5 does not reach the cluster network.

**Lab origins.** Local test servers live on loopback, which the policy blocks. `SCAN_LAB_ORIGINS` lists exact origins (scheme, host, port) that bypass the address and port checks. It is empty by default, logged loudly at startup, and not set in the Helm chart.

## Alternatives

- **Check the hostname with a deny list.** Names are not the boundary; addresses are.
- **Validate, then let the HTTP client resolve again.** That is the rebinding bug.
- **`net.BlockList`.** Works, but an explicit table returns the reason for a refusal and makes the embedded-IPv4 handling visible and testable.
- **An egress proxy.** A good production addition; more infrastructure than this project needs when NetworkPolicy gives the same guarantee.

## Consequences

- A host with any private address cannot be scanned, even if it also has public ones.
- Tests try to get round each step; see `packages/scan-core/src/net/*.test.ts`.
