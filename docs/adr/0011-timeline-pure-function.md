# 11. The login visualization is a pure function of time

**Status:** accepted · 2026-10-02

## Context

The walkthrough was a list of steps advanced by a timer, drawn with CSS transitions. It could not be scrubbed, an operation was never visible half done, and its behaviour could only be checked by looking at it.

## Decision

- A **score** declares what exists on the stage and when: objects, the path each travels, the operations they enter, and how each transforms.
- `sceneAt(score, t)` returns the complete state of the stage at time `t`: every object's position, opacity and transformation progress, the state of the channel, the active layer, and the caption. It has no side effects and does not depend on the previous frame.
- React renders that state as SVG. A single clock drives it: playing advances `t` with `requestAnimationFrame`; the scrubber, the keyboard and the landmark buttons set `t` directly.
- No CSS animations or transitions on the stage.

## Alternatives

- **GSAP master timeline.** Seekable and mature. It animates DOM nodes imperatively, so the state at a given time exists only in the browser, and tests would need a DOM and a rendering loop. A pure function can be asserted directly: "at 41.5 s the signature is half formed and has not left the server."
- **CSS animations with `animation-delay` scrubbing.** Fragile across many elements and still untestable.

## Consequences

- Scrubbing, replay, reduced motion and deep links ("open at Key Establishment in hybrid mode") are all the same operation: choose a `t`.
- Positions are expressed against named anchors, so the same score lays out as a row on wide screens and a column on narrow ones.
- Every frame re-renders the stage. It holds a few dozen SVG elements, which is well within budget.
