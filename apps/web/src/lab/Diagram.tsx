/**
 * The small SVG scenes in the lab. Each is a picture of a state, not an
 * animation playing on its own: the CSS reveals and transitions carry it
 * between states when a toggle changes. The grammar is the site's: solid
 * means private, outline means public, a dotted texture means post-quantum,
 * red means the attacker holds it.
 *
 * Every scene is laid out on one grid, 240 units wide and 104 high: the two
 * ends at the edges (browser 6..58, server 182..234), the thing the step
 * produces centred at x = 120, and anything paired at mirror positions about
 * it. Each glyph is drawn around its own origin, so placing it is one
 * translate and nothing sits off its centre.
 */

const MID = 120;
const Y = 46;

/** A key: round bow at the origin, bar to the right. Outline for public, filled for private; dotted ring for post-quantum. */
function Key({ x, y, solid, pq, hostile, flip }: { x: number; y: number; solid?: boolean; pq?: boolean; hostile?: boolean; flip?: boolean }) {
  const stroke = hostile ? 'var(--k-attacker)' : 'var(--k-session)';
  return (
    <g transform={`translate(${x} ${y})${flip ? ' scale(-1 1)' : ''}`}>
      {pq && <circle r="10.5" fill="none" stroke={stroke} strokeWidth="1.4" strokeDasharray="1.6 2.2" />}
      <circle r="6.5" fill={solid ? stroke : 'var(--paper)'} stroke={stroke} strokeWidth="2.2" />
      <path d="M6.5 0h12m-4 0v4.5m4-4.5v3.5" fill="none" stroke={stroke} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </g>
  );
}

/** A padlock centred at the origin. Open lifts the shackle; dotted shackle = post-quantum. */
function Lock({ x, y, open, pq, tone = 'secret', scale = 1 }: { x: number; y: number; open?: boolean; pq?: boolean; tone?: 'secret' | 'good' | 'bad'; scale?: number }) {
  const body = tone === 'secret' ? 'var(--signal)' : tone === 'good' ? 'var(--good)' : 'var(--bad)';
  return (
    <g transform={`translate(${x} ${y}) scale(${scale})`}>
      <path d={open ? 'M-6.5 -2v-6a6.5 6.5 0 0 1 13 0v1' : 'M-6.5 -2v-5a6.5 6.5 0 0 1 13 0v5'} fill="none" stroke="var(--ink)" strokeWidth="2.2" strokeLinecap="round" strokeDasharray={pq ? '2 2.2' : undefined} />
      <rect x="-9" y="-2" width="18" height="14" rx="2.5" fill={body} stroke="var(--ink)" strokeWidth="2.2" />
      <circle cy="5" r="1.8" fill="var(--ink)" />
    </g>
  );
}

/** A green disc with a check, centred at the origin: the mark the browser or the site puts on something it accepted. */
const Stamp = ({ x, y }: { x: number; y: number }) => (
  <g className="stamp" transform={`translate(${x} ${y})`}>
    <circle r="9" fill="var(--good)" />
    <path d="M-4.2 0.3l3 3 5.6-6.4" fill="none" stroke="var(--paper)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
  </g>
);

export type Step = 'kex' | 'cert' | 'token';

/** The diagram at the top of a process card: browser and server at the ends, what the step makes in the middle. */
export function ProcessScene({ step, pq, live }: { step: Step; pq: boolean; live: boolean }) {
  return (
    <svg className={`scene ${live ? 'live' : 'ghost'}`} viewBox="0 0 240 104" role="img" aria-hidden="true">
      <g className="ends">
        <rect className="node" x="6" y={Y - 16} width="52" height="32" rx="5" />
        <text className="node-t" x="32" y={Y + 4}>
          browser
        </text>
        <rect className="node" x="182" y={Y - 16} width="52" height="32" rx="5" />
        <text className="node-t" x="208" y={Y + 4}>
          server
        </text>
      </g>
      {step === 'kex' && (
        <g>
          {/* One wire. The two public halves meet in the middle, pointing at each other; the secret they make sits below. */}
          <path className="wire draw" d={`M58 ${Y}H182`} />
          <g className="pop">
            <Key x={MID - 46} y={Y} />
          </g>
          <g className="pop d2">
            <Key x={MID + 46} y={Y} flip />
          </g>
          <g className="pop d3">
            <Lock x={MID} y={Y + 2} pq={pq} />
          </g>
          <text className="scene-tag" x={MID} y="92">
            shared secret
          </text>
        </g>
      )}
      {step === 'cert' && (
        <g>
          <path className="wire draw" d={`M182 ${Y}H58`} />
          <g transform={`translate(${MID} ${Y})`}>
            <g className="pop d2">
              <rect className="card" x="-28" y="-19" width="56" height="38" rx="4" strokeDasharray={pq ? '3 2.5' : undefined} />
              <circle className="seal" cx="-16" cy="-6" r="5.5" />
              <path className="sig" d="M-6 -8h26M-6 -2h20M-20 7h40M-20 13h26" />
            </g>
            <g className="pop d3">
              <Stamp x={22} y={14} />
            </g>
          </g>
          <text className="scene-tag" x={MID} y="92">
            verified
          </text>
        </g>
      )}
      {step === 'token' && (
        <g>
          <path className="wire draw" d={`M182 ${Y}H58`} />
          <g transform={`translate(${MID} ${Y})`}>
            <g className="pop">
              <rect className="card" x="-28" y="-19" width="56" height="38" rx="4" strokeDasharray={pq ? '3 2.5' : undefined} />
              <rect className="t-h" x="-20" y="-11" width="11" height="6" rx="1" />
              <rect className="t-p" x="-6" y="-11" width="17" height="6" rx="1" />
              <rect className="t-s" x="14" y="-11" width="6" height="6" rx="1" />
              <path className="sig" d="M-20 2h40M-20 8h28M-20 14h18" />
            </g>
            <g className="pop d3">
              <Stamp x={22} y={14} />
            </g>
          </g>
          <text className="scene-tag" x={MID} y="92">
            signed by the site
          </text>
        </g>
      )}
    </svg>
  );
}

export type Phase = 'idle' | 'working' | 'won' | 'lost';
export type Job = 'recording' | 'site' | 'token';

/**
 * The attacker's attempt at one job: her copy on the left, the work in the
 * middle, what comes out on the right. The flow is the same for either
 * computer; the ending differs.
 */
export function AttackScene({ job, phase, pq }: { job: Job; phase: Phase; pq: boolean }) {
  const won = phase === 'won';
  const lost = phase === 'lost';
  const working = phase === 'working';
  const y = 40;
  return (
    <svg className={`a-scene phase-${phase}`} viewBox="0 0 240 80" role="img" aria-hidden="true">
      {/* What she starts with: a copy she took off the wire. */}
      <g className="hostile-src" transform={`translate(30 ${y})`}>
        <rect className="box" x="-20" y="-15" width="40" height="30" rx="4" />
        <path className="box-hatch" d="M-20 -15h40v30h-40z" />
        <path className="box-lines" d="M-11 -5h22M-11 1h22M-11 7h14" />
      </g>
      <g className="work" transform={`translate(${MID} ${y})`}>
        <circle className="ring r1" r="22" />
        <circle className="ring r2" r="15" />
        {working && <circle className="spark" cy="-22" r="3.2" />}
        {won && (
          <g className="got">
            <Key x={-6} y={0} solid hostile />
          </g>
        )}
        {lost && (
          <g className="nope">
            <path d="M-9 -9l18 18m0-18l-18 18" />
          </g>
        )}
      </g>
      <g className="out" transform={`translate(210 ${y})`}>
        {job === 'recording' ? (
          <Lock x={0} y={-1} open={won} tone={won ? 'bad' : 'good'} pq={pq} scale={1.5} />
        ) : (
          <g>
            <rect className={`card ${won ? 'forged' : 'held'}`} x="-20" y="-15" width="40" height="30" rx="4" />
            {won ? <path className="stamp-bad" d="M-9 0h18" /> : <path className="stamp-ok" d="M-7 0.5l4.5 4.5 9.5-10.5" />}
          </g>
        )}
      </g>
      <path className={`flow ${won ? 'won' : ''}`} d={`M50 ${y}H98M142 ${y}H190`} />
    </svg>
  );
}
