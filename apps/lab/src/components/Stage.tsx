import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';

/**
 * A picture of three machines and the things that travel between them.
 *
 *   [ someone's computer ] ───── [ Login service ]
 *                          └──── [ Payroll app   ]
 *
 * Each machine shows what it holds. A "packet" (a password, a token, a copied
 * key) sits at a machine's dock and slides along the wire when it is sent, so
 * you can see what leaves a machine and what never does.
 */
export type Spot = 'left' | 'service' | 'app';

export interface Packet {
  /** A new id makes the packet appear in place; the same id at a new spot makes it slide there. */
  id: string;
  at: Spot;
  /** Where a new packet starts before sliding to `at`. Without it, the packet appears at `at`. */
  from?: Spot;
  content: ReactNode;
}

type Points = Record<Spot, { x: number; y: number }>;

export interface StageProps {
  left: ReactNode;
  service: ReactNode;
  app: ReactNode;
  packet?: Packet;
  /** Which machine is doing something right now. */
  busy?: Spot;
  tone?: 'plain' | 'attack';
}

export function Stage({ left, service, app, packet, busy, tone = 'plain' }: StageProps) {
  const stage = useRef<HTMLDivElement>(null);
  const leftDock = useRef<HTMLSpanElement>(null);
  const serviceDock = useRef<HTMLSpanElement>(null);
  const appDock = useRef<HTMLSpanElement>(null);
  const [points, setPoints] = useState<Points>();

  // Machines change size as their contents change, so measure after every
  // render and on resize, and only update state when something actually moved.
  useLayoutEffect(() => {
    const measure = () => {
      const frame = stage.current?.getBoundingClientRect();
      if (!frame) return;
      const at = (el: HTMLElement | null) => {
        const r = el?.getBoundingClientRect();
        return r
          ? { x: Math.round(r.left + r.width / 2 - frame.left), y: Math.round(r.top + r.height / 2 - frame.top) }
          : { x: 0, y: 0 };
      };
      const next: Points = { left: at(leftDock.current), service: at(serviceDock.current), app: at(appDock.current) };
      setPoints((prev) => (prev && JSON.stringify(prev) === JSON.stringify(next) ? prev : next));
    };
    measure();
    const observer = new ResizeObserver(measure);
    if (stage.current) observer.observe(stage.current);
    return () => observer.disconnect();
  });

  // A new packet with a `from` is drawn there first, then moved on the next frame so it slides.
  const [spot, setSpot] = useState<Spot>();
  useEffect(() => {
    if (!packet) return setSpot(undefined);
    if (!packet.from) return setSpot(packet.at);
    setSpot(packet.from);
    const frame = requestAnimationFrame(() => requestAnimationFrame(() => setSpot(packet.at)));
    return () => cancelAnimationFrame(frame);
    // Runs when the packet or its destination changes, not on every render.
  }, [packet?.id, packet?.at]);

  const here = packet && points && spot ? points[spot] : undefined;

  return (
    <div className={`stage ${tone}`} ref={stage}>
      {points && (
        <svg className="wires" aria-hidden="true">
          <line x1={points.left.x} y1={points.left.y} x2={points.service.x} y2={points.service.y} />
          <line x1={points.left.x} y1={points.left.y} x2={points.app.x} y2={points.app.y} />
        </svg>
      )}

      <div className={`machine m-left ${busy === 'left' ? 'busy' : ''}`}>
        {left}
        <span className="dock" ref={leftDock} />
      </div>
      <div className={`machine m-service ${busy === 'service' ? 'busy' : ''}`}>
        <span className="dock" ref={serviceDock} />
        {service}
      </div>
      <div className={`machine m-app ${busy === 'app' ? 'busy' : ''}`}>
        <span className="dock" ref={appDock} />
        {app}
      </div>

      {packet && here && (
        <div className="packet" style={{ left: here.x, top: here.y }} key={packet.id}>
          {packet.content}
        </div>
      )}
    </div>
  );
}
