/**
 * The timeline engine (ADR 0011).
 *
 * A score says what exists on the stage and what happens to it, in beats with
 * start and end times. `sceneAt(score, t)` returns the complete state of the
 * stage at time t. It is a pure function: nothing is remembered between
 * calls, so scrubbing to any moment, in any order, gives the same picture,
 * and an operation scrubbed to its midpoint is drawn half done.
 *
 * Positions are named anchors ("b.op", "wire.tls.s") rather than coordinates,
 * so the same score lays out as a row on a wide screen and as a column on a
 * narrow one. Nothing here knows about the DOM.
 */

/** A named point on the stage. The layout decides where it is. */
export type Anchor = string;

export interface Prop {
  id: string;
  /** Which drawing to use. */
  kind: string;
  label: string;
  /** Free-form attributes for the drawing: colour identity, texture, text to show. */
  look?: Record<string, string | boolean | number>;
  /** Where it is and whether it is visible before anything happens. */
  home?: Anchor;
  visible?: boolean;
  /** Starting values of its channels. */
  channels?: Record<string, number>;
}

/**
 * One change to one prop, over a part of a beat. `span` is the fraction of
 * the beat it occupies: [0, 1] is the whole beat, [0.5, 1] its second half.
 */
export interface Action {
  prop: string;
  span?: [number, number];
  /** Put the prop here instantly when the action starts. */
  place?: Anchor;
  /** Travel here from wherever it is. */
  move?: Anchor;
  /** Fade in (true) or out (false). */
  show?: boolean;
  /** Drive named 0..1 values: how far a signature has formed, how scrambled a record is. */
  set?: Record<string, number>;
}

export interface Beat {
  id: string;
  start: number;
  end: number;
  /** Which layer of the system this beat belongs to. */
  layer: 'application' | 'tls' | 'network' | 'attacker';
  caption: string;
  /** The technical version, with values from this run. */
  detail?: string;
  /** Why this beat is or is not literally true: shown with the caption. */
  honesty?: string;
  actions: Action[];
}

export interface Landmark {
  id: string;
  label: string;
  t: number;
}

export interface Score {
  duration: number;
  props: Prop[];
  beats: Beat[];
  landmarks: Landmark[];
}

export interface PropState {
  /** The prop is between these two anchors, `p` of the way along. Settled props have from === to. */
  from: Anchor;
  to: Anchor;
  p: number;
  opacity: number;
  channels: Record<string, number>;
}

export interface Scene {
  t: number;
  beat: Beat;
  beatIndex: number;
  /** 0..1 through the current beat. */
  beatProgress: number;
  props: Record<string, PropState>;
}

export const NOWHERE: Anchor = 'nowhere';

const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x);
/** Ease in and out, so things start and stop rather than snap. */
const ease = (x: number) => x * x * (3 - 2 * x);
const lerp = (a: number, b: number, p: number) => a + (b - a) * p;

export function actionWindow(beat: Beat, action: Action): [number, number] {
  const [a, b] = action.span ?? [0, 1];
  const length = beat.end - beat.start;
  return [beat.start + a * length, beat.start + b * length];
}

export function sceneAt(score: Score, time: number): Scene {
  const t = Math.min(Math.max(time, 0), score.duration);
  const props: Record<string, PropState> = {};
  for (const prop of score.props) {
    const home = prop.home ?? NOWHERE;
    props[prop.id] = { from: home, to: home, p: 1, opacity: prop.visible ? 1 : 0, channels: { ...prop.channels } };
  }

  for (const beat of score.beats) {
    if (beat.start > t) break;
    for (const action of beat.actions) {
      const [start, end] = actionWindow(beat, action);
      if (t < start) continue;
      const state = props[action.prop];
      if (!state) continue;
      const p = end <= start ? 1 : ease(clamp01((t - start) / (end - start)));
      if (action.place !== undefined) {
        state.from = state.to = action.place;
        state.p = 1;
      }
      if (action.move !== undefined) {
        // It leaves from where the previous movement ended.
        state.from = state.to;
        state.to = action.move;
        state.p = p;
      }
      if (action.show !== undefined) state.opacity = lerp(state.opacity, action.show ? 1 : 0, p);
      if (action.set) {
        for (const [channel, target] of Object.entries(action.set)) state.channels[channel] = lerp(state.channels[channel] ?? 0, target, p);
      }
    }
  }

  let beatIndex = score.beats.findIndex((beat) => t < beat.end);
  if (beatIndex === -1) beatIndex = score.beats.length - 1;
  const beat = score.beats[beatIndex]!;
  return { t, beat, beatIndex, beatProgress: clamp01((t - beat.start) / (beat.end - beat.start)), props };
}

/**
 * Checks a score for mistakes that would make it draw wrongly when scrubbed:
 * gaps between beats, actions on props that do not exist, and two actions
 * changing the same aspect of a prop at the same time (the later one would
 * start from a half-finished value that depends on where the playhead is).
 */
export function scoreProblems(score: Score, anchors?: ReadonlySet<Anchor>): string[] {
  const problems: string[] = [];
  const known = new Set(score.props.map((p) => p.id));
  const busyUntil = new Map<string, number>();
  let previousEnd = 0;

  for (const prop of score.props) {
    if (anchors && prop.home && !anchors.has(prop.home)) problems.push(`${prop.id}: unknown home anchor ${prop.home}`);
  }
  for (const beat of score.beats) {
    if (Math.abs(beat.start - previousEnd) > 1e-9) problems.push(`${beat.id}: starts at ${beat.start}, previous beat ended at ${previousEnd}`);
    if (beat.end <= beat.start) problems.push(`${beat.id}: has no duration`);
    previousEnd = beat.end;
    const ordered = [...beat.actions].sort((a, b) => actionWindow(beat, a)[0] - actionWindow(beat, b)[0]);
    if (ordered.some((action, i) => action !== beat.actions[i])) problems.push(`${beat.id}: actions are not in start order`);
    for (const action of beat.actions) {
      const [start, end] = actionWindow(beat, action);
      if (!known.has(action.prop)) problems.push(`${beat.id}: unknown prop ${action.prop}`);
      for (const anchor of [action.place, action.move]) {
        if (anchors && anchor !== undefined && !anchors.has(anchor)) problems.push(`${beat.id}: unknown anchor ${anchor}`);
      }
      // Placing is instant; only travelling occupies the position for the length of the action.
      const aspects: [name: string, until: number][] = [
        ...(action.move !== undefined ? [['position', end] as [string, number]] : action.place !== undefined ? [['position', start] as [string, number]] : []),
        ...(action.show !== undefined ? [['opacity', end] as [string, number]] : []),
        ...Object.keys(action.set ?? {}).map((c) => [`channel ${c}`, end] as [string, number]),
      ];
      for (const [aspect, until] of aspects) {
        const key = `${action.prop} ${aspect}`;
        if ((busyUntil.get(key) ?? -Infinity) > start + 1e-9) problems.push(`${beat.id}: ${key} changes while an earlier change is still running`);
        busyUntil.set(key, until);
      }
    }
  }
  if (Math.abs(previousEnd - score.duration) > 1e-9) problems.push(`duration is ${score.duration} but the last beat ends at ${previousEnd}`);
  for (const landmark of score.landmarks) {
    if (!score.beats.some((beat) => Math.abs(beat.start - landmark.t) < 1e-9)) problems.push(`landmark ${landmark.id} is not at the start of a beat`);
  }
  return problems;
}
