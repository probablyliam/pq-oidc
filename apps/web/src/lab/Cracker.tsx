/**
 * The "working it out" readout: a row of hex digits that cycle while the
 * attacker is deriving a value, then settle on the real one when she succeeds,
 * or keep churning (and dim) when she cannot. It runs only when `active`
 * turns on, in response to the visitor switching the attacker's computer, so
 * it is a reaction to an action rather than a loop that plays on its own.
 */
import { useEffect, useRef, useState } from 'react';

const GLYPHS = '0123456789abcdef';
const rand = () => GLYPHS[Math.floor(Math.random() * GLYPHS.length)];

export interface CrackerProps {
  /** The value she is trying to recover, as a hex string with spaces. */
  target: string;
  /** True once she is working; false leaves the field blank. */
  active: boolean;
  /** Whether she gets it. Solved settles on `target`; unsolved never resolves. */
  solved: boolean;
}

export function Cracker({ target, active, solved }: CrackerProps) {
  const [text, setText] = useState('');
  const frame = useRef(0);

  useEffect(() => {
    if (!active) {
      setText('');
      return;
    }
    const chars = [...target];
    const start = performance.now();
    // Each position locks in turn over ~1.2s when solving; when not, nothing locks.
    const run = () => {
      const progress = solved ? Math.min((performance.now() - start) / 1200, 1) : 0;
      const locked = Math.floor(progress * chars.length);
      setText(chars.map((c, i) => (c === ' ' ? ' ' : i < locked ? c : rand())).join(''));
      if (!solved || progress < 1) frame.current = requestAnimationFrame(run);
    };
    frame.current = requestAnimationFrame(run);
    return () => cancelAnimationFrame(frame.current);
  }, [active, solved, target]);

  if (!active) return null;
  return (
    <output className={`cracker ${solved ? 'solved' : 'churning'}`} aria-live="off">
      {text}
    </output>
  );
}
