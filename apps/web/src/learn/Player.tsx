/**
 * The clock for the stage. It owns one number, the time, and everything on
 * screen follows from it: playing advances it, the scrubber and the keyboard
 * set it, and the stage is drawn for whatever it is.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { KindMark } from '../components/Finding.tsx';
import { sceneAt } from './engine.ts';
import { layoutFor } from './layout.ts';
import type { LoginScore } from './score.ts';
import { Stage } from './Stage.tsx';

const SPEEDS = [0.5, 1, 2];
const LAYERS = [
  { id: 'application', name: 'Application', does: 'the login itself, and the token' },
  { id: 'tls', name: 'TLS', does: 'key establishment, the server’s identity, encryption' },
  { id: 'attacker', name: 'Attacker', does: 'what she can do with what she recorded' },
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

const clock = (seconds: number) => `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, '0')}`;

export interface PlayerProps {
  score: LoginScore;
  attacker: boolean;
  /** Where to start, in seconds. */
  startAt: number;
  /** Start playing once the stage scrolls into view. */
  autoplay: boolean;
}

export function Player({ score, attacker, startAt, autoplay }: PlayerProps) {
  const [time, setTime] = useState(startAt);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const narrow = useMediaQuery('(max-width: 760px)');
  const reducedMotion = useMediaQuery('(prefers-reduced-motion: reduce)');
  const root = useRef<HTMLDivElement>(null);
  const autoplayed = useRef(false);

  const layout = useMemo(() => layoutFor(narrow ? 'column' : 'row', attacker), [narrow, attacker]);
  const scene = useMemo(() => sceneAt(score, time), [score, time]);
  const beat = score.beats[scene.beatIndex]!;
  const seek = useCallback((t: number) => setTime(Math.min(Math.max(t, 0), score.duration)), [score.duration]);

  // Playing: advance the time by however long the last frame took.
  useEffect(() => {
    if (!playing) return;
    let frame = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const elapsed = Math.min((now - last) / 1000, 0.1); // a background tab must not jump ahead
      last = now;
      setTime((t) => {
        const next = t + elapsed * speed;
        if (next >= score.duration) {
          setPlaying(false);
          return score.duration;
        }
        return next;
      });
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [playing, speed, score.duration]);

  // Start by itself the first time the stage is on screen, unless the visitor prefers no motion.
  useEffect(() => {
    if (!autoplay || reducedMotion || autoplayed.current || !root.current) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry?.isIntersecting && !autoplayed.current) {
          autoplayed.current = true;
          setPlaying(true);
        }
      },
      { threshold: 0.4 },
    );
    observer.observe(root.current);
    return () => observer.disconnect();
  }, [autoplay, reducedMotion]);

  const toBeat = (delta: number) => {
    setPlaying(false);
    // Back from the middle of a beat goes to its start; from its start, to the previous one.
    const index = delta < 0 && time - beat.start > 0.4 ? scene.beatIndex : scene.beatIndex + delta;
    const target = score.beats[Math.min(Math.max(index, 0), score.beats.length - 1)]!;
    // With reduced motion a step shows the finished state of the beat, since nothing will play it.
    seek(reducedMotion ? target.end - 0.001 : target.start);
  };
  const toLandmark = (delta: number) => {
    const times = score.landmarks.map((l) => l.t);
    const target = delta > 0 ? times.find((t) => t > time + 0.01) : [...times].reverse().find((t) => t < time - 0.4);
    setPlaying(false);
    seek(target ?? (delta > 0 ? score.duration : 0));
  };
  const toggle = () => {
    if (reducedMotion) return toBeat(1);
    if (time >= score.duration) seek(0);
    setPlaying((p) => !p);
  };

  function onScrubKey(event: KeyboardEvent<HTMLInputElement>) {
    const step = event.shiftKey ? 10 : 2;
    const keys: Record<string, () => void> = {
      ArrowLeft: () => seek(time - step),
      ArrowRight: () => seek(time + step),
      ArrowDown: () => seek(time - step),
      ArrowUp: () => seek(time + step),
      PageUp: () => toLandmark(-1),
      PageDown: () => toLandmark(1),
      Home: () => seek(0),
      End: () => seek(score.duration),
      ' ': toggle,
    };
    const action = keys[event.key];
    if (!action) return;
    event.preventDefault();
    if (event.key !== ' ') setPlaying(false);
    action();
  }

  const layers = LAYERS.filter((l) => l.id !== 'attacker' || attacker);

  return (
    <div className="player" ref={root}>
      <Stage score={score} scene={scene} layout={layout} />

      <div className="console">
      <div className="caption">
        <div className="caption-main" aria-live="polite">
          <p className="caption-text">{beat.caption}</p>
          {beat.honesty && (
            <p className="caption-honesty">
              <KindMark kind={beat.mark ?? 'model'} />
              <span>{beat.honesty}</span>
            </p>
          )}
          <details>
            <summary>Technical detail</summary>
            <p>{beat.detail}</p>
          </details>
        </div>
        <ol className="caption-layers" aria-label="Which layer this step belongs to">
          {layers.map((layer) => (
            <li key={layer.id} aria-current={beat.layer === layer.id ? 'true' : undefined}>
              <b>{layer.name}</b>
              <span>{layer.does}</span>
            </li>
          ))}
        </ol>
      </div>

      <div className="transport">
        <div className="transport-buttons">
          <button type="button" className="primary" onClick={toggle}>
            {reducedMotion ? 'Next step' : playing ? 'Pause' : 'Play'}
          </button>
          <button type="button" onClick={() => toBeat(-1)} disabled={time <= 0}>
            Back
          </button>
          <button type="button" onClick={() => toBeat(1)} disabled={time >= score.duration}>
            Next
          </button>
          <button
            type="button"
            onClick={() => {
              seek(0);
              setPlaying(!reducedMotion);
            }}
          >
            Replay
          </button>
          {!reducedMotion && (
            <div className="seg speed" role="group" aria-label="Speed">
              {SPEEDS.map((s) => (
                <button key={s} type="button" aria-pressed={speed === s} onClick={() => setSpeed(s)}>
                  {s}×
                </button>
              ))}
            </div>
          )}
          <span className="time">
            {clock(time)} / {clock(score.duration)}
          </span>
        </div>

        <div className="timeline">
          <input
            type="range"
            min={0}
            max={score.duration}
            step={0.05}
            value={time}
            aria-label="Timeline"
            aria-valuetext={`${clock(time)} of ${clock(score.duration)}. ${beat.caption}`}
            onChange={(event) => {
              setPlaying(false);
              seek(Number(event.target.value));
            }}
            onKeyDown={onScrubKey}
          />
          <ol className="landmarks">
            {score.landmarks.map((landmark, i) => {
              const next = score.landmarks[i + 1]?.t ?? score.duration;
              return (
                <li key={landmark.id} style={{ left: `${(landmark.t / score.duration) * 100}%`, width: `${((next - landmark.t) / score.duration) * 100}%` }}>
                  <button
                    type="button"
                    aria-current={time >= landmark.t && time < next ? 'step' : undefined}
                    onClick={() => {
                      setPlaying(false);
                      seek(landmark.t);
                    }}
                  >
                    {landmark.label}
                  </button>
                </li>
              );
            })}
          </ol>
        </div>
        <p className="fine keys">On the timeline: arrow keys move 2 seconds (Shift: 10), Page Up and Page Down jump between landmarks, Space plays or pauses.</p>
      </div>
      </div>
    </div>
  );
}
