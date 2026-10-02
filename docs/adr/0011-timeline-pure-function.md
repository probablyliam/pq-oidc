# 11. The login visualization is a pure function of time

**Status:** accepted · 2026-10-02 · rendering and interaction revised the same day (see Revision)

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
- ~~Every frame re-renders the stage. It holds a few dozen SVG elements, which is well within budget.~~ It was not: see below.

## Revision: the visitor does the login, and frames are drawn without React

The owner's review of the first version: "a really janky animation", a player "from the 1920's... we don't need back next replay and speed buttons", and "a glorified video instead of letting the person fake type something in". Three changes, none of which touch `sceneAt`:

- **The visitor logs in.** The login form on the stage is a real form. Pressing Log in runs the cryptography on what was typed (`runSession(mode, login)`), and the timeline plays from there: the typed password is what gets encrypted, what crosses the network as ciphertext, and what a quantum attacker's real decryption gives back on a classical site. The values never leave the page. An attacker records the network throughout; when the login ends the visitor chooses what she attacks with, and the timeline continues.
- **Drawing is imperative.** Re-rendering the SVG through React on every frame repainted the whole stage, textures and text included. The stage is now HTML built once per score; `Stage.draw(scene)` writes only what changed since the last frame, and everything that moves is its own compositor layer changed only by `transform` and `opacity`. The clock lives outside React state; React re-renders when the step changes, a few times a minute. Measured in headless Edge while playing: 990 frames in 6 s, median 6.1 ms, worst 7.7 ms, none over 25 ms.
- **One control.** Play or pause, and a timeline to drag, with the landmarks named under it. Back, Next, Replay and the speed buttons are gone. The score is authored slowly and shown at a fixed 3x.

`draw` keeps no state beyond a cache of what it last wrote, so the property this decision was made for still holds: the picture depends only on `t`. The tests are unchanged in kind, and now also assert that a watched-only score and an attack score share every beat of the login, so one can replace the other mid-way without anything on the stage moving.
