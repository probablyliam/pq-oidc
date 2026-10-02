import { useCallback, useEffect, useState } from 'react';

/**
 * Plays a list of events one at a time. `index` is how many events have
 * happened (0 = not started). One timer drives it; pausing, stepping and
 * replaying only ever move the index.
 */
export function useSequence(length: number, stepMs: number) {
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing) return;
    if (index >= length) return setPlaying(false);
    const timer = window.setTimeout(() => setIndex((i) => i + 1), stepMs);
    return () => window.clearTimeout(timer);
  }, [playing, index, length, stepMs]);

  const clamp = useCallback((i: number) => Math.max(1, Math.min(length, i)), [length]);

  return {
    index,
    playing,
    finished: length > 0 && index >= length,
    /** Start from the first event and play through. */
    start: useCallback(() => {
      setIndex(1);
      setPlaying(true);
    }, []),
    play: useCallback(() => {
      setIndex((i) => (i >= length ? 1 : Math.max(1, i)));
      setPlaying(true);
    }, [length]),
    pause: useCallback(() => setPlaying(false), []),
    /** Stepping by hand stops the automatic playback. */
    step: useCallback(
      (delta: number) => {
        setPlaying(false);
        setIndex((i) => clamp(i + delta));
      },
      [clamp],
    ),
    goTo: useCallback(
      (i: number) => {
        setPlaying(false);
        setIndex(clamp(i));
      },
      [clamp],
    ),
    reset: useCallback(() => {
      setPlaying(false);
      setIndex(0);
    }, []),
  };
}
