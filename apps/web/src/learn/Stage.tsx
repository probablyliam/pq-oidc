/**
 * The stage. React builds it once for a score and a layout; after that every
 * frame is drawn by `draw(scene)`, which moves and fades the elements
 * directly. Things that move are their own compositor layers and change only
 * by transform and opacity, so a frame repaints nothing that is standing
 * still. `draw` remembers only what it last wrote: whatever the playhead
 * says is exactly what is on screen (ADR 0011).
 *
 * The drawing grammar is the one in styles/base.css: solid means private,
 * outline means public, a dotted lattice texture means post-quantum, and a
 * red ring means the attacker holds it.
 */
import { forwardRef, useImperativeHandle, useLayoutEffect, useMemo, useRef } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import type { Prop, Scene } from './engine.ts';
import type { Layout, Rect } from './layout.ts';
import type { Actor, LoginScore } from './score.ts';

const CHIP_W = 110;
const CHIP_H = 46;
const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x);
const round = (x: number) => Math.round(x * 1000) / 1000;

const ICONS: Record<string, string> = {
  key: 'M-1.5 0a3.2 3.2 0 1 0-6.4 0a3.2 3.2 0 0 0 6.4 0Zm0 0h9.5m-3.4 0v3.2m3.4-3.2v2.4',
  data: 'M-6.5-6h8l4 4v8h-12zM-3.5 0h6M-3.5 3h6',
  secret: 'M-2.5-6.5a3 3 0 0 1 6 0v3M-5.5-3.5h11v9h-11z',
  signature: 'M-6.5 5.5v-7m3 7v-11m3 11v-5m3 5v-9m3 9v-4',
  sealed: 'M-3.5-1.5v-2a3.5 3.5 0 0 1 7 0v2M-6-1.5h12v8h-12z',
  cert: 'M-6.5-6.5h13v10h-13zM-3.5-3h7M-3.5 0h4M3.5 3.5l1.5 4 1.5-1.5 1.5 1.5 1-4',
};

/** A login in transit: readable text gives way, character by character, to the real ciphertext. */
function scrambled(plain: string, cipher: string, amount: number): string {
  const length = 20;
  const from = plain.padEnd(length).slice(0, length);
  const to = cipher.replaceAll(' ', '').padEnd(length, '0').slice(0, length);
  const cut = Math.round(amount * length);
  return (to.slice(0, cut) + from.slice(cut)).trimEnd();
}

const box = (r: Rect): CSSProperties => ({ left: r.x, top: r.y, width: r.w, height: r.h });

function Chip({ prop, scale }: { prop: Prop; scale: number }) {
  const look = prop.look ?? {};
  const classes = [
    'chip',
    `kind-${prop.kind}`,
    look.hue ? `hue-${look.hue}` : '',
    look.solid ? 'solid' : 'outline',
    look.lattice === 'half' ? 'lattice-half' : look.lattice ? 'lattice' : '',
    look.hostile ? 'hostile' : '',
    prop.channels?.formed !== undefined ? 'forms' : '',
  ].join(' ');
  return (
    <div className={classes} data-chip={prop.id} style={{ width: CHIP_W * scale, height: CHIP_H * scale }}>
      {look.plain !== undefined && <i className="chip-cipher" />}
      {prop.kind === 'token' ? (
        <span className="token-strip">
          <i className="t-header" />
          <i className="t-payload" />
          <i className="t-signature" />
        </span>
      ) : (
        <svg className="chip-icon" viewBox="-9 -9 18 18" aria-hidden="true">
          <path d={ICONS[prop.kind] ?? ICONS.data} />
        </svg>
      )}
      <span className="chip-label">{prop.label}</span>
      <span className="chip-note">{look.plain !== undefined ? String(look.plain) : String(look.note ?? '')}</span>
    </div>
  );
}

export interface StageProps {
  score: LoginScore;
  layout: Layout;
  /** What the browser's screen shows: the login form, the wait, and the signed-in page. */
  screen: { form: ReactNode; waiting: ReactNode; welcome: ReactNode };
}

export interface StageHandle {
  draw: (scene: Scene) => void;
}

export const Stage = forwardRef<StageHandle, StageProps>(function Stage({ score, layout, screen }, handle) {
  const fit = useRef<HTMLDivElement>(null);
  const root = useRef<HTMLDivElement>(null);
  /** The last value written for each thing `draw` controls, so a frame only touches what changed. */
  const written = useRef(new Map<string, string | number | boolean>());
  const k = layout.glyphScale;
  const row = layout.orientation === 'row';
  const { tls, app } = layout.lanes;
  const attackerPanel = layout.panels.attacker;
  const chips = useMemo(() => score.props.filter((prop) => !['screen', 'wire', 'trust', 'attacker'].includes(prop.kind)), [score]);
  const actors: Actor[] = attackerPanel ? ['b', 's', 'm'] : ['b', 's'];

  // The stage is drawn in its own units and scaled as a whole to the width it is given.
  useLayoutEffect(() => {
    const outer = fit.current;
    if (!outer) return;
    const resize = () => root.current?.style.setProperty('zoom', String(outer.clientWidth / layout.width));
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(outer);
    return () => observer.disconnect();
  }, [layout.width]);

  // A different layout or score means different elements: forget what was written to the old ones.
  const found = useRef(new Map<string, HTMLElement | null>());
  useLayoutEffect(() => {
    written.current.clear();
    found.current.clear();
  }, [layout, score]);

  useImperativeHandle(
    handle,
    () => ({
      draw(scene) {
        const stage = root.current;
        if (!stage) return;
        const find = (selector: string) => {
          let element = found.current.get(selector);
          if (element === undefined) found.current.set(selector, (element = stage.querySelector<HTMLElement>(selector)));
          return element;
        };
        const put = (key: string, value: string | number | boolean, apply: () => void) => {
          if (written.current.get(key) === value) return;
          written.current.set(key, value);
          apply();
        };
        const fade = (key: string, selector: string, opacity: number) => put(key, round(opacity), () => find(selector)?.style.setProperty('opacity', String(round(opacity))));

        const [w, h] = [CHIP_W * k, CHIP_H * k];
        for (const prop of chips) {
          const state = scene.props[prop.id];
          const [a, b] = state ? [layout.anchors[state.from], layout.anchors[state.to]] : [];
          const visible = state !== undefined && a !== undefined && b !== undefined && state.opacity > 0.01;
          const id = prop.id;
          put(`${id} shown`, visible, () => find(`[data-chip="${id}"]`)?.style.setProperty('visibility', visible ? 'visible' : 'hidden'));
          if (!visible) continue;
          const at = `translate3d(${(a.x + (b.x - a.x) * state.p - w / 2).toFixed(2)}px, ${(a.y + (b.y - a.y) * state.p - h / 2).toFixed(2)}px, 0)`;
          put(`${id} at`, at, () => find(`[data-chip="${id}"]`)?.style.setProperty('transform', at));
          fade(`${id} opacity`, `[data-chip="${id}"]`, state.opacity);
          // Things on the move pass over what is standing still.
          put(`${id} moving`, state.p < 1, () => find(`[data-chip="${id}"]`)?.style.setProperty('z-index', state.p < 1 ? '4' : '3'));
          const { formed, cipher } = state.channels;
          if (formed !== undefined) put(`${id} formed`, round(formed), () => find(`[data-chip="${id}"]`)?.style.setProperty('--formed', String(round(formed))));
          if (cipher !== undefined && prop.look?.plain !== undefined) {
            put(`${id} cipher`, round(cipher), () => find(`[data-chip="${id}"]`)?.style.setProperty('--cipher', String(round(cipher))));
            const dark = cipher > 0.5;
            put(`${id} dark`, dark, () => {
              const chip = find(`[data-chip="${id}"]`);
              if (!chip) return;
              chip.dataset.dark = String(dark);
              if (id === 'cred') chip.querySelector('.chip-label')!.textContent = dark ? 'Encrypted login' : prop.label;
            });
            const text = scrambled(String(prop.look.plain), String(prop.look.cipher ?? ''), cipher);
            put(`${id} text`, text, () => {
              const note = find(`[data-chip="${id}"] .chip-note`);
              if (note) note.textContent = text;
            });
          }
        }

        const wire = scene.props.wire?.channels ?? {};
        const [sealed, tunnel] = [wire.sealed ?? 0, wire.tunnel ?? 0];
        fade('tls fill', '.lane.tls .lane-fill', sealed);
        fade('tls open', '.lane.tls .lane-label.open', 1 - sealed);
        fade('tls sealed', '.lane.tls .lane-label.sealed', sealed);
        fade('app fill', '.lane.app .lane-fill', tunnel);
        fade('app open', '.lane.app .lane-label.open', 1 - tunnel);
        fade('app sealed', '.lane.app .lane-label.sealed', tunnel);
        fade('trust', '.trust-check', scene.props.trust?.channels.checked ?? 0);

        // The browser's screen: the form, then the wait, then the signed-in page.
        const { waiting = 0, welcome = 0 } = scene.props.screen?.channels ?? {};
        const layers: [name: string, opacity: number][] = [
          ['form', 1 - waiting],
          ['waiting', waiting * (1 - welcome)],
          ['welcome', welcome],
        ];
        for (const [name, opacity] of layers) {
          fade(`screen ${name}`, `.screen-${name}`, opacity);
          // Only what is fully there can be typed into or pressed.
          put(`screen ${name} live`, opacity > 0.98, () => {
            const layer = find(`.screen-${name}`);
            if (layer) layer.inert = opacity <= 0.98;
          });
        }

        const beat = score.beats[scene.beatIndex]!;
        for (const actor of actors) {
          const op = beat.ops?.find((o) => o.actor === actor);
          const [start, end] = op?.span ?? [0, 0];
          const progress = op ? clamp01((scene.beatProgress - start) / (end - start)) : 0;
          const active = op !== undefined && scene.beatProgress >= start && scene.beatProgress <= end;
          const chamber = `[data-chamber="${actor}"]`;
          put(`${actor} op`, `${scene.beatIndex}`, () => {
            const el = find(chamber);
            if (!el) return;
            el.dataset.named = String(op !== undefined);
            el.dataset.ok = String(op?.result?.ok ?? true);
            el.querySelector('.chamber-label')!.textContent = op?.label ?? '';
            el.querySelector('.chamber-result span')!.textContent = op?.result?.text ?? '';
          });
          put(`${actor} active`, active, () => find(chamber)?.setAttribute('data-active', String(active)));
          put(`${actor} progress`, round(progress), () => find(`${chamber} .chamber-progress`)?.style.setProperty('transform', `scaleX(${round(progress)})`));
          fade(`${actor} result`, `${chamber} .chamber-result`, op?.result ? clamp01((scene.beatProgress - end) / 0.06) : 0);
        }
      },
    }),
    [score, layout, chips, k, actors.length],
  );

  const laneLabel = (state: 'open' | 'sealed', what: string, how: string) => (
    <p className={`lane-label ${state}`}>
      <span className="lane-text">
        <b>{what}</b>
        {row ? `: ${how}` : how}
      </span>
    </p>
  );
  const trustAt = layout.anchors['b.trust'];
  const mallory = layout.anchors['m.self'];
  const [tapTls, tapApp] = [layout.anchors['tap.tls']!, layout.anchors['tap.app']!];

  return (
    <div className={`stage-fit ${layout.orientation}`} ref={fit} style={{ aspectRatio: `${layout.width} / ${layout.height}` }}>
      <div className={`stage ${layout.orientation}`} ref={root} style={{ width: layout.width, height: layout.height, ['--k' as string]: k }}>
        <div className="panel-box browser" style={box(layout.panels.browser)}>
          <p className="panel-title">
            Browser <span>this computer</span>
          </p>
        </div>
        <div className="panel-box server" style={box(layout.panels.server)}>
          <p className="panel-title">
            Server <span>payroll.example</span>
          </p>
        </div>
        {attackerPanel && (
          <div className="panel-box attacker" style={box(attackerPanel)}>
            <p className="panel-title">
              Mallory <span>{row ? 'an attacker copying everything that crosses the network' : 'copying the network'}</span>
            </p>
          </div>
        )}

        {row && (
          <p className="network-title" style={{ left: tls.x, width: tls.w }}>
            Network
          </p>
        )}
        <div className="lane tls" style={box(tls)}>
          <i className="lane-fill" />
          {laneLabel('open', 'TLS handshake', 'in the open, anyone can read it')}
          {laneLabel('sealed', 'TLS handshake', 'encrypted from here on')}
        </div>
        <div className="lane app" style={box(app)}>
          <i className="lane-fill" />
          {laneLabel('open', 'Application data', 'no channel yet')}
          {laneLabel('sealed', 'Application data', row ? 'inside the secure channel' : 'in the channel')}
        </div>
        {attackerPanel && (
          <svg className="tap" width={layout.width} height={layout.height} viewBox={`0 0 ${layout.width} ${layout.height}`} aria-hidden="true">
            {row ? (
              <line x1={tapTls.x} y1={tls.y + tls.h / 2} x2={tapTls.x} y2={attackerPanel.y} />
            ) : (
              <path d={`M${tapTls.x} ${tapTls.y}H${app.x - 18}V${attackerPanel.y - 8}M${tapApp.x} ${tapApp.y}H${app.x - 18}`} />
            )}
            <circle cx={tapTls.x} cy={tapTls.y} r={5 * k} />
            <circle cx={tapApp.x} cy={tapApp.y} r={5 * k} />
          </svg>
        )}

        <div className="screen" style={box(layout.screen)}>
          <p className="screen-site">payroll.example</p>
          <div className="screen-layer screen-form">{screen.form}</div>
          <div className="screen-layer screen-waiting">{screen.waiting}</div>
          <div className="screen-layer screen-welcome">{screen.welcome}</div>
        </div>

        {actors.map((actor) => {
          const at = layout.anchors[`${actor}.op`]!;
          return (
            <div key={actor} className="chamber" data-chamber={actor} style={{ left: at.x - 64 * k, top: at.y - 34 * k, width: 128 * k, height: 68 * k }}>
              <span className="chamber-label" />
              <i className="chamber-progress" />
              <span className="chamber-result">
                <svg viewBox="-12 -12 24 24" aria-hidden="true">
                  <path className="mark-ok" d="M-8 0l5 5 10-11" />
                  <path className="mark-fail" d="M-7-7l14 14m0-14l-14 14" />
                </svg>
                <span />
              </span>
            </div>
          );
        })}

        {trustAt && (
          <div className="trust" style={{ left: trustAt.x - (CHIP_W * k) / 2, top: trustAt.y - (CHIP_H * k) / 2, width: CHIP_W * k, height: CHIP_H * k }}>
            <span>Authorities this browser trusts</span>
            <svg className="trust-check" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M4 12l5 5 11-12" />
            </svg>
          </div>
        )}
        {mallory && (
          <svg className="mallory" viewBox="-24 -25 48 52" style={{ left: mallory.x - 24 * k, top: mallory.y - 25 * k, width: 48 * k, height: 52 * k }} aria-hidden="true">
            <circle cx="0" cy="-12" r="11" />
            <path d="M-22 26a22 20 0 0 1 44 0z" />
          </svg>
        )}

        {chips.map((prop) => (
          <Chip key={prop.id} prop={prop} scale={k} />
        ))}
      </div>
    </div>
  );
});
