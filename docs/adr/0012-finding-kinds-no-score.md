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
