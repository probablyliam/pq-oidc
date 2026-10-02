/**
 * Draws the stage for one moment in time. Everything here is a function of
 * the scene it is given: there are no transitions, timers or CSS animations,
 * so whatever the playhead says is exactly what is on screen (ADR 0011).
 *
 * The drawing grammar is the one in styles/base.css: solid means private,
 * outline means public, a dotted lattice texture means post-quantum, and a
 * red ring means the attacker holds it.
 */
import type { Prop, PropState, Scene } from './engine.ts';
import type { Layout, Point, Rect } from './layout.ts';
import type { Actor, LoginScore, StageOp } from './score.ts';

const CHIP_W = 110;
const CHIP_H = 46;
const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x);

const ICONS: Record<string, string> = {
  key: 'M-1.5 0a3.2 3.2 0 1 0-6.4 0a3.2 3.2 0 0 0 6.4 0Zm0 0h9.5m-3.4 0v3.2m3.4-3.2v2.4',
  data: 'M-6.5-6h8l4 4v8h-12zM-3.5 0h6M-3.5 3h6',
  secret: 'M-2.5-6.5a3 3 0 0 1 6 0v3M-5.5-3.5h11v9h-11z',
  signature: 'M-6.5 5.5v-7m3 7v-11m3 11v-5m3 5v-9m3 9v-4',
  sealed: 'M-3.5-1.5v-2a3.5 3.5 0 0 1 7 0v2M-6-1.5h12v8h-12z',
  cert: 'M-6.5-6.5h13v10h-13zM-3.5-3h7M-3.5 0h4M3.5 3.5l1.5 4 1.5-1.5 1.5 1.5 1-4',
};

/** Splits a label into at most two lines of similar length. */
function wrap(label: string): string[] {
  if (label.length <= 15) return [label];
  const words = label.split(' ');
  let best = 1;
  for (let i = 1; i < words.length; i++) {
    const [a, b] = [words.slice(0, i).join(' ').length, words.slice(0, best).join(' ').length];
    if (Math.abs(a - label.length / 2) < Math.abs(b - label.length / 2)) best = i;
  }
  return [words.slice(0, best).join(' '), words.slice(best).join(' ')];
}

function position(layout: Layout, state: PropState): Point | undefined {
  const [a, b] = [layout.anchors[state.from], layout.anchors[state.to]];
  if (!a || !b) return undefined;
  return { x: a.x + (b.x - a.x) * state.p, y: a.y + (b.y - a.y) * state.p };
}

/** A login in transit: readable text gives way, character by character, to the real ciphertext. */
function scrambled(plain: string, cipher: string, amount: number): string {
  const length = 20;
  const from = plain.padEnd(length).slice(0, length);
  const to = cipher.replaceAll(' ', '').padEnd(length, '0').slice(0, length);
  const cut = Math.round(amount * length);
  return to.slice(0, cut) + from.slice(cut);
}

function Chip({ prop, state, at, scale }: { prop: Prop; state: PropState; at: Point; scale: number }) {
  const look = prop.look ?? {};
  const formed = state.channels.formed ?? 1;
  const cipher = state.channels.cipher ?? 0;
  const lines = wrap(cipher > 0.5 && prop.id === 'cred' ? 'Encrypted login' : prop.label);
  const note = look.plain !== undefined ? scrambled(String(look.plain), String(look.cipher ?? ''), cipher) : String(look.note ?? '');
  const classes = ['chip', `kind-${prop.kind}`, look.hue ? `hue-${look.hue}` : '', look.solid ? 'solid' : 'outline', look.hostile ? 'hostile' : ''].join(' ');
  // Something being made grows from the left; its text arrives once there is room for it.
  const width = Math.max(8, CHIP_W * formed);
  const textOpacity = clamp01((formed - 0.55) / 0.3);
  const lattice = look.lattice === 'half' ? { x: -CHIP_W / 2 + width / 2, w: width / 2 } : look.lattice ? { x: -CHIP_W / 2, w: width } : undefined;
  const labelY = lines.length === 2 ? -9 : -3;

  return (
    <g className={classes} transform={`translate(${at.x} ${at.y}) scale(${scale})`} opacity={state.opacity}>
      <rect className="body" x={-CHIP_W / 2} y={-CHIP_H / 2} width={width} height={CHIP_H} rx="4" />
      {prop.kind === 'sealed' && <rect className="hatch" x={-CHIP_W / 2} y={-CHIP_H / 2} width={width} height={CHIP_H} rx="4" />}
      {look.plain !== undefined && <rect className="cipher-fill" x={-CHIP_W / 2} y={-CHIP_H / 2} width={CHIP_W} height={CHIP_H} rx="4" opacity={cipher} />}
      {lattice && <rect className="lattice" x={lattice.x} y={-CHIP_H / 2} width={lattice.w} height={CHIP_H} rx="4" />}
      {prop.kind === 'token' && (
        <g className="token-strip">
          <rect className="t-header" x={-CHIP_W / 2 + 4} y={-CHIP_H / 2 + 4} width="18" height="7" />
          <rect className="t-payload" x={-CHIP_W / 2 + 23} y={-CHIP_H / 2 + 4} width="34" height="7" />
          <rect className="t-signature" x={-CHIP_W / 2 + 58} y={-CHIP_H / 2 + 4} width={48 * formed} height="7" />
        </g>
      )}
      <g opacity={textOpacity} className={cipher > 0.5 ? 'on-dark' : undefined}>
        {prop.kind !== 'token' && <path className="icon" d={ICONS[prop.kind] ?? ICONS.data} transform={`translate(${-CHIP_W / 2 + 13} ${labelY + (lines.length === 2 ? 4 : 0)})`} />}
        {lines.map((line, i) => (
          <text key={i} className="label" x={prop.kind === 'token' ? -CHIP_W / 2 + 6 : -CHIP_W / 2 + 25} y={labelY + i * 12 + (prop.kind === 'token' ? 9 : 0)}>
            {line}
          </text>
        ))}
        <text className="note" x={-CHIP_W / 2 + 6} y={CHIP_H / 2 - 6}>
          {note}
        </text>
      </g>
      {look.hostile && <rect className="ring" x={-CHIP_W / 2 - 2.5} y={-CHIP_H / 2 - 2.5} width={width + 5} height={CHIP_H + 5} rx="6" />}
    </g>
  );
}

function Panel({ rect, title, subtitle, className, scale }: { rect: Rect; title: string; subtitle: string; className: string; scale: number }) {
  return (
    <g className={`panel-box ${className}`}>
      <rect x={rect.x} y={rect.y} width={rect.w} height={rect.h} rx="4" />
      <text className="panel-title" x={rect.x + 14} y={rect.y + 22 * Math.min(scale, 1.2)} fontSize={15 * scale}>
        {title}
        <tspan className="panel-sub" dx="8" fontSize={12 * scale}>
          {subtitle}
        </tspan>
      </text>
    </g>
  );
}

/** The login form, then "logging in", then the signed-in page: all driven by the scene. */
function Screen({ rect, channels, scale }: { rect: Rect; channels: Record<string, number>; scale: number }) {
  const { typed = 0, pressed = 0, waiting = 0, welcome = 0 } = channels;
  const password = '••••••••••••'.slice(0, Math.round(typed * 12));
  const user = 'alice'.slice(0, Math.round(clamp01(typed * 2.2) * 5));
  const s = scale;
  const fieldW = rect.w * 0.34;
  return (
    <g className="screen" transform={`translate(${rect.x} ${rect.y})`}>
      <rect className="screen-frame" width={rect.w} height={rect.h} rx="3" />
      <text className="screen-site" x={12} y={20 * s} fontSize={12 * s}>
        payroll.example
      </text>
      <g opacity={1 - waiting}>
        <rect className="field" x={12} y={32 * s} width={fieldW} height={24 * s} />
        <text className="field-text" x={18} y={32 * s + 16 * s} fontSize={12 * s}>
          {user}
        </text>
        <rect className="field" x={22 + fieldW} y={32 * s} width={fieldW} height={24 * s} />
        <text className="field-text" x={28 + fieldW} y={32 * s + 16 * s} fontSize={12 * s}>
          {password}
        </text>
        <rect className={pressed > 0.5 ? 'button pressed' : 'button'} x={32 + fieldW * 2} y={32 * s} width={70 * s} height={24 * s} rx="3" />
        <text className={pressed > 0.5 ? 'button-text pressed' : 'button-text'} x={32 + fieldW * 2 + 35 * s} y={32 * s + 16 * s} fontSize={12 * s} textAnchor="middle">
          Log in
        </text>
      </g>
      <text className="screen-status" x={12} y={50 * s} fontSize={14 * s} opacity={waiting * (1 - welcome)}>
        Logging in as alice…
      </text>
      <g opacity={welcome}>
        <text className="screen-welcome" x={12} y={48 * s} fontSize={17 * s}>
          Welcome, Alice
        </text>
        <text className="screen-status" x={12} y={66 * s} fontSize={12 * s}>
          Your payslips are ready.
        </text>
      </g>
    </g>
  );
}

function Lanes({ layout, sealed, tunnel, tapped }: { layout: Layout; sealed: number; tunnel: number; tapped: boolean }) {
  const { tls, app } = layout.lanes;
  const k = layout.glyphScale;
  const row = layout.orientation === 'row';
  // In a row the label sits above its lane on one line; in a column there is only room for two short lines inside it.
  const label = (rect: Rect, what: string, state: string, className: string, opacity: number) =>
    row ? (
      <text className={`lane-label ${className}`} x={rect.x + rect.w / 2} y={rect.y - 7} fontSize={11.5} textAnchor="middle" opacity={opacity}>
        {what}: {state}
      </text>
    ) : (
      <text className={`lane-label ${className}`} x={rect.x + rect.w / 2} y={rect.y + 15 * k} fontSize={10.5 * k} textAnchor="middle" opacity={opacity}>
        <tspan fontWeight="700">{what}</tspan>
        <tspan x={rect.x + rect.w / 2} dy={13 * k}>
          {state}
        </tspan>
      </text>
    );
  return (
    <g className="lanes">
      <text className="network-title" x={tls.x + (row ? tls.w / 2 : 8)} y={row ? 30 : tls.y + 16 * k} fontSize={15 * k} textAnchor={row ? 'middle' : 'start'} opacity={row ? 1 : 0}>
        Network
      </text>
      <rect className="lane open" x={tls.x} y={tls.y} width={tls.w} height={tls.h} />
      <rect className="lane sealed" x={tls.x} y={tls.y} width={tls.w} height={tls.h} opacity={sealed} />
      {label(tls, 'TLS handshake', 'in the open, anyone can read it', 'open', 1 - sealed)}
      {label(tls, 'TLS handshake', 'encrypted from here on', 'sealed', sealed)}
      <rect className="lane none" x={app.x} y={app.y} width={app.w} height={app.h} />
      <rect className="lane tunnel" x={app.x} y={app.y} width={app.w} height={app.h} opacity={tunnel} />
      {label(app, 'Application data', 'no channel yet', 'open', 1 - tunnel)}
      {label(app, 'Application data', row ? 'inside the secure channel' : 'in the channel', 'sealed', tunnel)}
      {tapped && layout.panels.attacker && (
        <g className="tap">
          {row ? (
            <line x1={layout.anchors['tap.tls']!.x} y1={tls.y + tls.h / 2} x2={layout.anchors['tap.tls']!.x} y2={layout.panels.attacker.y} />
          ) : (
            <path
              d={`M${layout.anchors['tap.tls']!.x} ${layout.anchors['tap.tls']!.y}H${app.x - 18}V${layout.panels.attacker.y - 8}M${layout.anchors['tap.app']!.x} ${layout.anchors['tap.app']!.y}H${app.x - 18}`}
            />
          )}
          <circle cx={layout.anchors['tap.tls']!.x} cy={layout.anchors['tap.tls']!.y} r={5 * k} />
          <circle cx={layout.anchors['tap.app']!.x} cy={layout.anchors['tap.app']!.y} r={5 * k} />
        </g>
      )}
    </g>
  );
}

function Chamber({ at, scale, op, beatProgress }: { at: Point; scale: number; op: StageOp | undefined; beatProgress: number }) {
  const [start, end] = op?.span ?? [0, 0];
  const working = op ? clamp01((beatProgress - start) / (end - start)) : 0;
  const active = op !== undefined && beatProgress >= start && beatProgress <= end;
  const resultOpacity = op?.result ? clamp01((beatProgress - end) / 0.06) : 0;
  return (
    <g className={`chamber ${active ? 'active' : ''} ${op ? 'named' : ''}`} transform={`translate(${at.x} ${at.y}) scale(${scale})`}>
      <rect className="chamber-box" x="-64" y="-34" width="128" height="68" rx="4" />
      {op && (
        <>
          <text className="chamber-label" x="0" y="-41" textAnchor="middle">
            {op.label}
          </text>
          <rect className="chamber-progress" x="-64" y="30" width={128 * working} height="4" />
        </>
      )}
      {op?.result && (
        <g className={op.result.ok ? 'result ok' : 'result fail'} opacity={resultOpacity}>
          <path d={op.result.ok ? 'M-8 0l5 5 10-11' : 'M-7-7l14 14m0-14l-14 14'} transform="translate(0 0)" />
          <text x="0" y="52" textAnchor="middle">
            {op.result.text}
          </text>
        </g>
      )}
    </g>
  );
}

export interface StageProps {
  score: LoginScore;
  scene: Scene;
  layout: Layout;
}

export function Stage({ score, scene, layout }: StageProps) {
  const k = layout.glyphScale;
  const wire = scene.props.wire?.channels ?? {};
  const beat = score.beats[scene.beatIndex]!;
  const opFor = (actor: Actor) => beat.ops?.find((op) => op.actor === actor);
  const tapped = layout.panels.attacker !== undefined;
  const chips = score.props.filter((prop) => !['screen', 'wire', 'trust', 'attacker'].includes(prop.kind));
  // Things on the move are drawn last, so they pass over what is standing still.
  const ordered = [...chips].sort((a, b) => Number(scene.props[a.id]!.p < 1) - Number(scene.props[b.id]!.p < 1));
  const trust = scene.props.trust;
  const trustAt = layout.anchors['b.trust'];
  const mallory = layout.anchors['m.self'];

  return (
    <svg className={`stage ${layout.orientation}`} viewBox={`0 0 ${layout.width} ${layout.height}`} role="img" aria-label={beat.caption}>
      <defs>
        <pattern id="tex-lattice" width="7" height="7" patternUnits="userSpaceOnUse">
          <circle cx="3.5" cy="3.5" r="1.15" />
        </pattern>
        <pattern id="tex-hatch" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <line x1="0" y1="0" x2="0" y2="7" />
        </pattern>
      </defs>

      <Lanes layout={layout} sealed={wire.sealed ?? 0} tunnel={wire.tunnel ?? 0} tapped={tapped} />
      <Panel rect={layout.panels.browser} title="Browser" subtitle="Alice’s computer" className="browser" scale={k} />
      <Panel rect={layout.panels.server} title="Server" subtitle="payroll.example" className="server" scale={k} />
      {layout.panels.attacker && (
        <Panel rect={layout.panels.attacker} title="Mallory" subtitle={layout.orientation === 'row' ? 'an attacker copying everything that crosses the network' : 'copying the network'} className="attacker" scale={k} />
      )}

      <Screen rect={layout.screen} channels={scene.props.screen?.channels ?? {}} scale={k} />
      {(['b', 's', ...(tapped ? ['m'] : [])] as Actor[]).map((actor) => (
        <Chamber key={actor} at={layout.anchors[`${actor}.op`]!} scale={k} op={opFor(actor)} beatProgress={scene.beatProgress} />
      ))}

      {trust && trustAt && (
        <g className="trust" transform={`translate(${trustAt.x} ${trustAt.y}) scale(${k})`}>
          <rect x={-CHIP_W / 2} y={-CHIP_H / 2} width={CHIP_W} height={CHIP_H} rx="4" />
          <text className="label" x={-CHIP_W / 2 + 8} y="-6">
            Authorities this
          </text>
          <text className="label" x={-CHIP_W / 2 + 8} y="7">
            browser trusts
          </text>
          <path className="trust-check" d="M32 4l5 5 10-11" opacity={trust.channels.checked ?? 0} />
        </g>
      )}
      {mallory && (
        <g className="mallory" transform={`translate(${mallory.x} ${mallory.y}) scale(${k})`}>
          <circle cx="0" cy="-12" r="11" />
          <path d="M-22 26a22 20 0 0 1 44 0z" />
        </g>
      )}

      {ordered.map((prop) => {
        const state = scene.props[prop.id]!;
        const at = position(layout, state);
        if (!at || state.opacity <= 0.01) return null;
        return <Chip key={prop.id} prop={prop} state={state} at={at} scale={k} />;
      })}
    </svg>
  );
}
