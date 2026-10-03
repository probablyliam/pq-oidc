/**
 * The small SVG scenes in the lab. Each is a function of what the site uses
 * and of a phase, so it is a picture of a state, not an animation playing on
 * its own: CSS reveals and transitions carry it between states when a toggle
 * changes. A dotted texture means post-quantum, a solid fill means a secret,
 * red means the attacker holds it. Same grammar as the rest of the site.
 *
 * Every scene is laid out on the same grid: 240 wide, the two ends at the
 * edges (browser 6..54, server 186..234), the thing the step produces centred
 * at x = 120, and anything paired placed at mirror positions about it. A
 * result mark (check or cross) is centred on the thing it judges.
 */

const MID = 120;

/** A key: outline for public, filled for private, dotted ring for post-quantum. Its visual centre is 4.5 right of `x`. */
function Key({ x, y, solid, pq, hostile }: { x: number; y: number; solid?: boolean; pq?: boolean; hostile?: boolean }) {
  const stroke = hostile ? 'var(--k-attacker)' : 'var(--k-session)';
  return (
    <g transform={`translate(${x} ${y})`}>
      <circle cx="0" cy="0" r="6" fill={solid ? stroke : 'var(--paper)'} stroke={stroke} strokeWidth="2" />
      <path d="M5 0h10m-4 0v4m4-4v3" stroke={stroke} strokeWidth="2" fill="none" strokeLinecap="round" />
      {pq && <circle cx="0" cy="0" r="9.5" fill="none" stroke={stroke} strokeWidth="1.3" strokeDasharray="1.5 2" />}
    </g>
  );
}
/** Where to put a key so that its visual centre lands on `cx`. */
const keyAt = (cx: number) => cx - 4.5;

/** A padlock, centred on (x, y). Open reveals what it protected; dotted shackle = post-quantum. */
function Lock({ x, y, open, pq, tone = 'secret', scale = 1 }: { x: number; y: number; open?: boolean; pq?: boolean; tone?: 'secret' | 'good' | 'bad'; scale?: number }) {
  const body = tone === 'secret' ? 'var(--signal)' : tone === 'good' ? 'var(--good)' : 'var(--bad)';
  return (
    <g transform={`translate(${x} ${y}) scale(${scale})`}>
      <path d={open ? 'M-6-6a6 6 0 0 1 12 0' : 'M-6-2v-4a6 6 0 0 1 12 0v4'} fill="none" stroke="var(--ink)" strokeWidth="2" strokeDasharray={pq ? '2 2' : undefined} />
      <rect x="-8" y="-2" width="16" height="13" rx="2" fill={body} stroke="var(--ink)" strokeWidth="2" />
    </g>
  );
}

/** A check mark centred on (x, y). */
const Check = ({ x, y }: { x: number; y: number }) => <path d={`M${x - 7} ${y}l5 5 9-11`} />;

export type Step = 'kex' | 'cert' | 'token';

/** The diagram at the top of a process card: browser and server at the ends, what the step makes in the middle. */
export function ProcessScene({ step, pq, live }: { step: Step; pq: boolean; live: boolean }) {
  return (
    <svg className={`scene ${live ? 'live' : 'ghost'}`} viewBox="0 0 240 92" role="img" aria-hidden="true">
      <g className="ends">
        <rect className="node" x="6" y="30" width="48" height="32" rx="4" />
        <text className="node-t" x="30" y="50">
          browser
        </text>
        <rect className="node" x="186" y="30" width="48" height="32" rx="4" />
        <text className="node-t" x="210" y="50">
          server
        </text>
      </g>
      {step === 'kex' && (
        <g>
          {/* Two shares cross, one each way; the secret they make sits between the wires. */}
          <path className="wire draw" d="M54 40H186" />
          <path className="wire draw d2" d="M186 52H54" />
          <g className="pop">
            <Key x={keyAt(MID + 34)} y={40} />
          </g>
          <g className="pop d2">
            <Key x={keyAt(MID - 34)} y={52} />
          </g>
          <g className="pop d3">
            <Lock x={MID} y={46.5} pq={pq} />
          </g>
          <text className="scene-tag" x={MID} y="76">
            shared secret
          </text>
        </g>
      )}
      {step === 'cert' && (
        <g>
          <path className="wire draw" d="M186 46H54" />
          <g transform={`translate(${MID - 24} 31)`}>
            <g className="pop d2">
              <rect className="card" x="0" y="0" width="48" height="30" rx="3" strokeDasharray={pq ? '3 2' : undefined} />
              <path className="sig" d="M7 10h22M7 16h30M7 22h16" />
            </g>
          </g>
          <g className="pop d3 check">
            <Check x={MID} y={46} />
          </g>
          <text className="scene-tag" x={MID} y="76">
            verified
          </text>
        </g>
      )}
      {step === 'token' && (
        <g>
          <path className="wire draw" d="M186 46H54" />
          <g transform={`translate(${MID - 24} 31)`}>
            <g className="pop">
              <rect className="card" x="0" y="0" width="48" height="30" rx="3" strokeDasharray={pq ? '3 2' : undefined} />
              <rect className="t-h" x="6" y="7" width="9" height="5" />
              <rect className="t-p" x="18" y="7" width="14" height="5" />
              <rect className="t-s" x="35" y="7" width="7" height="5" />
              <path className="sig" d="M7 19h34M7 24h20" />
            </g>
          </g>
          <g className="pop d3 check">
            <Check x={MID} y={46} />
          </g>
          <text className="scene-tag" x={MID} y="76">
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
  const Y = 39;
  return (
    <svg className={`a-scene phase-${phase}`} viewBox="0 0 240 78" role="img" aria-hidden="true">
      {/* What she starts with: a copy she took off the wire. Same box, 40 by 30, at both ends. */}
      <g className="hostile-src">
        <rect className="box" x="10" y={Y - 15} width="40" height="30" rx="3" />
        <path className="box-hatch" d={`M10 ${Y - 15}h40v30H10z`} />
      </g>
      <g className="work">
        <circle className="ring r1" cx={MID} cy={Y} r="22" />
        <circle className="ring r2" cx={MID} cy={Y} r="15" />
        {working && <circle className="spark" cx={MID} cy={Y - 22} r="3" />}
        {won && (
          <g className="got">
            <Key x={keyAt(MID)} y={Y} solid hostile />
          </g>
        )}
        {lost && (
          <g className="nope">
            <path d={`M${MID - 10} ${Y - 10}l20 20m0-20l-20 20`} />
          </g>
        )}
      </g>
      <g className="out">
        {job === 'recording' ? (
          <Lock x={210} y={Y + 0.8} open={won} tone={won ? 'bad' : 'good'} pq={pq} scale={1.6} />
        ) : (
          <g transform={`translate(190 ${Y - 15})`}>
            <rect className={`card ${won ? 'forged' : 'held'}`} x="0" y="0" width="40" height="30" rx="3" />
            {won ? <path className="stamp-bad" d="M11 15h18" /> : <path className="stamp-ok" d="M13 15l5 5 9-11" />}
          </g>
        )}
      </g>
      <path className={`flow ${won ? 'won' : ''}`} d={`M50 ${Y}H98M142 ${Y}H190`} />
    </svg>
  );
}
