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
- "Could not determine" is a normal, expected outcome and is shown as prominently as the rest.
