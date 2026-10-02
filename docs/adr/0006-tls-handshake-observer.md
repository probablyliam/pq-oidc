# 6. Observe TLS with our own ClientHello instead of a TLS library's API

**Status:** accepted · 2026-10-02

## Context

The scanner has to report the key-exchange group a server negotiates, including hybrid groups such as X25519MLKEM768, and the signature scheme the server uses to prove it holds the certificate key.

Checked on Node 25.9 (OpenSSL 3.5.5):

- `tls.connect` negotiates X25519MLKEM768 with servers that support it, but `getEphemeralKeyInfo()` returns `{}` for hybrid groups. The API cannot tell hybrid from "unknown".
- The peer's CertificateVerify scheme is not exposed to clients.
- A library handshake shows one outcome for one client configuration. It cannot answer "which groups does this server accept?" or "what does a client without post-quantum support get?"

## Decision

`packages/scan-core` builds ClientHello messages itself and parses the reply.

- ServerHello and HelloRetryRequest are plaintext: version, cipher suite and selected group are read directly.
- To enumerate support for a group, the scanner offers only that group with an empty `key_share`. RFC 8446 §4.2.8 lets the server answer with a HelloRetryRequest naming the group; an alert means it is not supported. No key material is needed.
- For the main handshake the scanner completes the key exchange (X25519, P-256, P-384, ML-KEM-768/1024 and their hybrids through `node:crypto`), runs the TLS 1.3 key schedule, decrypts the server's flight and reads EncryptedExtensions, Certificate, CertificateVerify and Finished. It verifies the CertificateVerify signature and the Finished MAC, then closes the connection. It never sends application data.
- TLS 1.2 replies are parsed in plaintext (Certificate, ServerKeyExchange).
- Trust decisions are not made by this code. Chain validation uses Node/OpenSSL in a separate connection.

## Alternatives

- **Node's TLS API.** Cannot observe the hybrid group (above).
- **Shell out to `openssl s_client` or an oqs-provider build.** Needs OpenSSL 3.5+ on every host, parses human-oriented text, and spawning a process per probe with a user-supplied hostname is its own risk. The Git-for-Windows OpenSSL here is 3.2.
- **Infer hybrid support from the Server header or CDN.** That is guessing; the brief forbids it.

## Consequences

- Roughly a thousand lines of protocol code to maintain. It is a measuring instrument, not a security boundary: no secrets are sent through it.
- Verified three ways: the key schedule against the RFC 8448 trace, full handshakes against OpenSSL servers started in tests (independent implementation), and a few public sites.
- Only groups in the scanner's registry can be recognised by name; others are reported by code point.
- QUIC is not covered.
