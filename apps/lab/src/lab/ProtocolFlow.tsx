import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { holdings } from './events.ts';
import type { Actor, LabEvent, Packet, Thing } from './events.ts';
import { AuthenticityTag, LayerStack, OperationView, ThingView } from './pieces.tsx';

/**
 * Three actors that never move (browser, network, server), with an optional
 * attacker on the network. Whatever the current event sends is drawn crossing
 * the network; whatever it computes is drawn inside the actor that computes it;
 * what each actor holds accumulates underneath.
 */
export interface ProtocolFlowProps {
  events: LabEvent[];
  /** How many events have happened (0 = not started). */
  index: number;
  browserScreen: ReactNode;
  serverNote?: string;
  /** Things an actor has before the sequence starts. */
  initial?: Partial<Record<Actor, Thing[]>>;
  attacker?: boolean;
  controls: ReactNode;
  idleHint: string;
}

/** A packet starts at its sender and, a frame later, is told where to go, so the browser animates the trip. */
function TravellingPacket({ packet, order }: { packet: Packet; order: number }) {
  const [arrived, setArrived] = useState(false);
  useEffect(() => {
    const frame = requestAnimationFrame(() => requestAnimationFrame(() => setArrived(true)));
    return () => cancelAnimationFrame(frame);
  }, []);
  return (
    <div className={`packet at-${arrived ? packet.to : packet.from} lane-${order}`}>
      <ThingView thing={packet.thing} />
    </div>
  );
}

function ActorPanel({
  actor,
  name,
  sub,
  event,
  held,
  children,
}: {
  actor: Actor;
  name: string;
  sub: string;
  event: LabEvent | undefined;
  held: Thing[];
  children?: ReactNode;
}) {
  const working = event?.operation?.at === actor;
  return (
    <div className={`actor actor-${actor} ${working ? 'working' : ''}`}>
      <header>
        <b>{name}</b>
        <span>{sub}</span>
      </header>
      {children}
      {working && event?.operation && <OperationView operation={event.operation} />}
      {held.length > 0 && (
        <div className="held">
          <span className="held-label">Holds</span>
          {held.map((thing, i) => (
            <ThingView key={i} thing={thing} />
          ))}
        </div>
      )}
    </div>
  );
}

export function ProtocolFlow({ events, index, browserScreen, serverNote, initial, attacker, controls, idleHint }: ProtocolFlowProps) {
  const [showWhat, setShowWhat] = useState(true);
  const [showDetail, setShowDetail] = useState(false);
  const event = index > 0 ? events[index - 1] : undefined;
  const held = holdings(events, index, initial);
  // The attack happens after the login, so its connection is already encrypted.
  const secured = attacker || events.slice(0, index).some((e) => e.secures);

  return (
    <div className="lab">
      <div className={`flow ${attacker ? 'with-attacker' : ''}`}>
        <ActorPanel actor="browser" name="Browser" sub="Alice’s computer" event={event} held={held.browser}>
          <div className="screen">{browserScreen}</div>
        </ActorPanel>

        <div className={`net ${secured ? 'secured' : ''}`}>
          <span className="net-name">Network</span>
          <span className="net-state">{secured ? 'encrypted channel' : 'open: anyone can watch'}</span>
          <div className="wire" />
          {event?.packets?.map((packet, i) => (
            <TravellingPacket key={`${event.id}-${i}`} packet={packet} order={i} />
          ))}
        </div>

        <ActorPanel actor="server" name="Server" sub="payroll.example" event={event} held={held.server}>
          {serverNote && <p className="actor-note">{serverNote}</p>}
        </ActorPanel>

        {attacker && (
          <ActorPanel actor="attacker" name="Mallory" sub="an attacker watching the network" event={event} held={held.attacker} />
        )}
      </div>

      <div className="narration">
        <div className="narration-text" aria-live="polite">
          {event ? (
            <>
              <p className="step-count">
                Step {index} of {events.length}
              </p>
              <h3 className={event.outcome ?? ''}>{event.title}</h3>
              <details open={showWhat} onToggle={(e) => setShowWhat(e.currentTarget.open)}>
                <summary>What just happened?</summary>
                <p>{event.what}</p>
                <details open={showDetail} onToggle={(e) => setShowDetail(e.currentTarget.open)}>
                  <summary>Technical detail</summary>
                  <p>{event.detail}</p>
                  <AuthenticityTag value={event.authenticity} />
                </details>
              </details>
            </>
          ) : (
            <p className="idle-hint">{idleHint}</p>
          )}
        </div>
        <LayerStack active={event?.layer} />
      </div>

      {controls}
    </div>
  );
}

/** Play, pause, step and replay, plus one dot per event. */
export function PlayerControls({
  events,
  player,
}: {
  events: LabEvent[];
  player: { index: number; playing: boolean; play: () => void; pause: () => void; step: (d: number) => void; goTo: (i: number) => void; start: () => void };
}) {
  const started = player.index > 0;
  return (
    <div className="player">
      <div className="player-buttons">
        <button type="button" disabled={!started} onClick={player.playing ? player.pause : player.play}>
          {player.playing ? 'Pause' : 'Play'}
        </button>
        <button type="button" disabled={!started || player.index <= 1} onClick={() => player.step(-1)}>
          Back
        </button>
        <button type="button" disabled={!started || player.index >= events.length} onClick={() => player.step(1)}>
          Next
        </button>
        <button type="button" disabled={!started} onClick={player.start}>
          Replay
        </button>
      </div>
      <ol className="dots">
        {events.map((e, i) => (
          <li key={e.id}>
            <button
              type="button"
              className={`layer-${e.layer}`}
              title={e.title}
              aria-label={`Step ${i + 1}: ${e.title}`}
              aria-current={i + 1 === player.index ? 'step' : undefined}
              disabled={!started}
              onClick={() => player.goTo(i + 1)}
            >
              {i + 1}
            </button>
          </li>
        ))}
      </ol>
    </div>
  );
}
