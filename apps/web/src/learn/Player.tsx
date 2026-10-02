/**
 * The clock for the stage. It owns one number, the time. Playing advances it
 * and the timeline sets it; each change is drawn straight onto the stage,
 * without a React render, so a frame costs only what moved. React hears
 * about the things that change a few times a minute: which step this is,
 * and whether the clock is running.
 */
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent, ReactNode } from 'react';
import { KindMark } from '../components/Finding.tsx';
import { sceneAt } from './engine.ts';
import { layoutFor } from './layout.ts';
import type { LoginScore } from './score.ts';
import { Stage } from './Stage.tsx';
import type { StageHandle, StageProps } from './Stage.tsx';

/** Seconds of the score per second on the clock. The score is written slowly; this is the pace it is shown at. */
const RATE = 3;
const LAYERS = [
  { id: 'application', name: 'Application' },
  { id: 'tls', name: 'TLS' },
  { id: 'attacker', name: 'Attacker' },
] as const;

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const media = window.matchMedia(query);
    const update = () => setMatches(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, [query]);
  return matches;
}

/** An instruction from outside: go to this moment, and play from it or wait there. */
export interface Cue {
  id: number;
  at: number;
  play: boolean;
}

export interface PlayerProps {
  score: LoginScore;
  cue: Cue;
  screen: StageProps['screen'];
  /** Shown in place of a caption before anything has happened. */
  invitation: string;
  /** Pressing play before anything has happened is the same as pressing Log in. */
  onStart: () => void;
  /** What to do next, offered once the timeline has run out. */
  ending?: ReactNode;
}

type Edge = 'start' | 'middle' | 'end';

export function Player({ score, cue, screen, invitation, onStart, ending }: PlayerProps) {
  const narrow = useMediaQuery('(max-width: 900px)');
  const reducedMotion = useMediaQuery('(prefers-reduced-motion: reduce)');
  const layout = useMemo(() => layoutFor(narrow ? 'column' : 'row', true), [narrow]);
  const root = useRef<HTMLDivElement>(null);
  const stage = useRef<StageHandle>(null);
  const scrubber = useRef<HTMLInputElement>(null);
  const time = useRef(cue.at);
  const [playing, setPlaying] = useState(false);
  const [beatIndex, setBeatIndex] = useState(() => sceneAt(score, cue.at).beatIndex);
  const [edge, setEdge] = useState<Edge>('start');
  const shown = useRef({ beatIndex, edge });

  /** Puts the stage, and the timeline, at a moment. */
  const show = useCallback(
    (t: number) => {
      const at = Math.min(Math.max(t, 0), score.duration);
      time.current = at;
      const scene = sceneAt(score, at);
      stage.current?.draw(scene);
      if (scrubber.current) {
        scrubber.current.value = String(at);
        scrubber.current.style.setProperty('--played', `${(at / score.duration) * 100}%`);
      }
      const now: Edge = at <= 0.001 ? 'start' : at >= score.duration - 0.001 ? 'end' : 'middle';
      if (scene.beatIndex !== shown.current.beatIndex) setBeatIndex((shown.current.beatIndex = scene.beatIndex));
      if (now !== shown.current.edge) setEdge((shown.current.edge = now));
    },
    [score],
  );

  // A new score or arrangement is drawn where the clock already is.
  useLayoutEffect(() => show(time.current), [show, layout]);

  // A cue from outside: Log in was pressed, an attack was chosen, or a link asked for a moment.
  useLayoutEffect(() => {
    // With reduced motion nothing plays, so a cue shows the finished state of the step it points at.
    show(reducedMotion && cue.play ? sceneAt(score, cue.at).beat.end - 0.001 : cue.at);
    setPlaying(cue.play && !reducedMotion);
    // Something is about to happen on the stage: bring all of it into view.
    if (cue.play) root.current?.scrollIntoView({ block: 'start', behavior: reducedMotion ? 'auto' : 'smooth' });
    // Only a new cue moves the clock: a new score alone keeps its place.
  }, [cue.id]);

  // Playing: advance the time by however long the last frame took.
  useEffect(() => {
    if (!playing) return;
    let frame = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const elapsed = Math.min((now - last) / 1000, 0.1); // a background tab must not jump ahead
      last = now;
      const next = time.current + elapsed * RATE;
      if (next >= score.duration) {
        show(score.duration);
        setPlaying(false);
        return;
      }
      show(next);
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [playing, score, show]);

  // A shorter score can arrive a render before the clock is redrawn on it.
  const beat = score.beats[Math.min(beatIndex, score.beats.length - 1)]!;
  const idle = edge === 'start' && !playing;

  const toLandmark = (delta: number) => {
    const times = score.landmarks.map((l) => l.t);
    const target = delta > 0 ? times.find((t) => t > time.current + 0.01) : [...times].reverse().find((t) => t < time.current - 0.4);
    setPlaying(false);
    show(target ?? (delta > 0 ? score.duration : 0));
  };
  const nextStep = () => {
    const current = sceneAt(score, time.current);
    const atEnd = time.current >= current.beat.end - 0.01;
    show(score.beats[Math.min(current.beatIndex + (atEnd ? 1 : 0), score.beats.length - 1)]!.end - 0.001);
  };
  const toggle = () => {
    if (playing) return setPlaying(false);
    if (time.current <= 0.001) return onStart();
    if (reducedMotion) return nextStep();
    if (time.current >= score.duration - 0.001) show(0);
    setPlaying(true);
  };

  function onScrubKey(event: KeyboardEvent<HTMLInputElement>) {
    const step = event.shiftKey ? 10 : 2;
    const keys: Record<string, () => void> = {
      ArrowLeft: () => show(time.current - step),
      ArrowRight: () => show(time.current + step),
      ArrowDown: () => show(time.current - step),
      ArrowUp: () => show(time.current + step),
      PageUp: () => toLandmark(-1),
      PageDown: () => toLandmark(1),
      Home: () => show(0),
      End: () => show(score.duration),
      ' ': toggle,
    };
    const action = keys[event.key];
    if (!action) return;
    event.preventDefault();
    if (event.key !== ' ') setPlaying(false);
    action();
  }

  const playLabel = playing ? 'Pause' : reducedMotion && !idle ? 'Next step' : 'Play';

  return (
    <div className="player" ref={root}>
      <Stage ref={stage} score={score} layout={layout} screen={screen} />

      <div className="console">
        <div className="caption">
          <p className="caption-text" aria-live="polite">
            {idle ? invitation : beat.caption}
          </p>
          {edge === 'end' && !playing && ending}
          {!idle && (
            <div className="caption-meta">
              <ol className="caption-layers" aria-label="Which layer this step belongs to">
                {LAYERS.map((layer) => (
                  <li key={layer.id} aria-current={beat.layer === layer.id ? 'true' : undefined}>
                    {layer.name}
                  </li>
                ))}
              </ol>
              <details>
                <summary>Technical detail</summary>
                <p>{beat.detail}</p>
                {beat.honesty && (
                  <p className="caption-honesty">
                    <KindMark kind={beat.mark ?? 'model'} />
                    <span>{beat.honesty}</span>
                  </p>
                )}
              </details>
            </div>
          )}
        </div>

        <div className="transport">
          <button type="button" className={`play ${playing ? 'is-playing' : ''}`} onClick={toggle} aria-label={playLabel} title={playLabel}>
            <svg viewBox="0 0 24 24" aria-hidden="true">
              {playing ? <path d="M7 5h3.5v14H7zM13.5 5H17v14h-3.5z" /> : reducedMotion && !idle ? <path d="M6 5l8 7-8 7zM15.5 5H18v14h-2.5z" /> : <path d="M8 5l11 7-11 7z" />}
            </svg>
          </button>
          <div className="timeline">
            <input
              ref={scrubber}
              type="range"
              min={0}
              max={score.duration}
              step={0.05}
              defaultValue={cue.at}
              aria-label="Timeline"
              aria-valuetext={idle ? invitation : beat.caption}
              onChange={(event) => {
                setPlaying(false);
                show(Number(event.target.value));
              }}
              onKeyDown={onScrubKey}
            />
            <ol className="landmarks">
              {score.landmarks.map((landmark, i) => {
                const next = score.landmarks[i + 1]?.t ?? score.duration;
                // The first one is the start itself, and too short a stretch to carry a name.
                if (landmark.t === 0) return null;
                return (
                  <li key={landmark.id} style={{ left: `${(landmark.t / score.duration) * 100}%`, width: `${((next - landmark.t) / score.duration) * 100}%` }}>
                    <button
                      type="button"
                      aria-current={!idle && beat.start >= landmark.t && beat.start < next ? 'step' : undefined}
                      onClick={() => {
                        setPlaying(false);
                        show(landmark.t);
                      }}
                    >
                      {landmark.label}
                    </button>
                  </li>
                );
              })}
            </ol>
          </div>
        </div>
      </div>
    </div>
  );
}
