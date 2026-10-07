# 12. Findings are labelled by how they are known; there is no score

**Status:** accepted · 2026-10-02

## Context

A single "quantum readiness" number hides that a system has several cryptographic layers with different threats and different deadlines, and it invites invented precision.

## Decision

A report is a list of findings grouped by layer (TLS key establishment, TLS server authentication, symmetric protection, transport policy, token signing, dependencies). Each finding has exactly one kind:

- **Real observation**: read off the wire or from a document the target published. Carries the evidence (for example the group code point and the probe that saw it).
- **Inference**: a conclusion from observations, with the reasoning written out and the observations it rests on.
- **Could not determine**: something the scanner looked for and could not establish, with the reason.

The learning pages use a third label, **conceptual simulation**, for anything that cannot be executed, such as a quantum attack.

Each layer also gets a quantum-exposure class, which is itself an inference with a stated rule:

- *harvest-now-decrypt-later exposure* for classical key establishment,
- *forgery exposure once a capable quantum computer exists* for classical signatures (not retroactive),
- *reduced margin* for symmetric primitives and hashes (Grover), never "broken",
- *no known quantum attack* for ML-KEM, ML-DSA and SLH-DSA.

## Consequences

- No number to compare across sites. Comparison is per layer, per finding.

## Addition: a verdict in plain words, in front of the findings

The first results page showed every finding at once, and the owner's reaction was "what the heck am I even looking at". The findings are unchanged; what comes first is now a summary (`packages/scan-core/src/summary.ts`):

- One verdict: **Not quantum-safe**, **Partly quantum-safe**, **Quantum-safe**, or **Could not tell**.
- Three questions with short answers: can a recording of this connection be read later (key establishment), can someone pretend to be this site (the certificate), can someone fake a sign-in (the token signature).
- Everything else, including every finding with its evidence and its observed / inferred / could-not-determine mark, under "Technical details".

This is still not a score. The verdict is a stated function of the layer assessments: not safe if recorded traffic is exposed now; safe only if key establishment and both signatures are; unknown if the scan could not see key establishment; partly otherwise. A sign-in the scan could not see does not block "safe" but is shown as "cannot tell from outside". The rules are in the file and under test.
- "Could not determine" is a normal, expected outcome and is shown as prominently as the rest.

## Addition (2026-10-07): rules that keep a finding honest

An audit of the report's wording, and two independent reviews of the fixes, found statements that went past what a scan shows. The rules that came out of it, under test in `packages/scan-core/src/assess.test.ts` and `summary.test.ts`:

- **An observation says what was seen, never why.** Handshakes that receive different certificates are reported as that. Whether the server chose by what each client offered is only suggested when the handshake that offered ML-DSA got a post-quantum certificate and one that did not got a classical one; a service run on several machines behind one address hands out different certificates to identical clients (seen on login.microsoftonline.com).
- **No answer is not a refusal.** "TLS 1.3 clients without post-quantum key exchange are refused" and "TLS 1.2 is not accepted" need a TLS alert, or a connection closed or reset the same way on a second attempt. A handshake that timed out, or was cut once, is "could not determine": something between the scanner and the server may have done it. The same rule decides whether a group is "not accepted".
- **A refusal is only about what the handshake changed.** The classical handshake leaves out post-quantum groups and ML-DSA signatures together, so a server with a post-quantum certificate refuses it whatever key exchange it accepts. For such a server a further handshake keeps the ML-DSA signatures and offers only classical groups (`classical-kex-client`), and only its refusal counts. The same holds for certificates: a handshake that keeps the post-quantum groups and offers only classical signatures (`classical-sig-client`) shows whether a classical certificate is still handed out, which is what a browser with hybrid key exchange and no ML-DSA would be given.
- **Authentication is judged by what clients accept, as far as a scan can see it.** A post-quantum certificate does not stop impersonation while clients still accept a classical one for the same name. So a server that gives a classical certificate to a handshake that did not offer ML-DSA is *migrating* (forgery exposure remains), and a chain that is post-quantum throughout is described as exactly that, with the note that what clients accept is not visible. Token keys follow the same rule.
- **An algorithm the scanner does not recognise is "could not determine".** It is not counted as classical, and nothing is said about a quantum computer breaking it. This holds for certificate keys, chain signatures and token keys. A classical part that was seen still decides the matter, whatever else is unrecognised.
- **"Quantum-safe" needs every client.** The verdict is "safe" only when key establishment has no known attack for every client that can connect, not when it depends on the client, and not while the service's own metadata lists only classical token signatures.
- **A claim about browsers rests on the group browsers use.** "In an up-to-date browser" is said only when the scanner's own browser-shaped handshake was given X25519MLKEM768.

And one about time. The wording states what a result depends on ("a public site cannot change this alone: certificate authorities must issue quantum-safe certificates, and browsers must stop accepting the older kind") instead of the state of the world on the day it was written ("browsers do not accept such certificates yet"). The first stays true as browsers and certificate authorities move; the second has to be found and rewritten each time they do. Dated facts belong in the dated documents (`findings.md`, these records), with their date. The dated claim about products left in the result text is that current versions of the major browsers support X25519MLKEM768, which is checked against the scan as above; the other standing claims (post-quantum groups exist only in TLS 1.3; no such computer is known to exist) are stated as such.

Not covered: when a server holds both kinds of certificate, the trust check is made on the certificate the scanner's own HTTPS request received, which may not be the one a browser is given.
