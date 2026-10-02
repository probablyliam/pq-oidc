/**
 * The small SVG scenes in the lab. Each is a function of what the site uses
 * and of a phase, so it is a picture of a state, not an animation playing on
 * its own: CSS reveals and transitions carry it between states when a toggle
 * changes. A dotted texture means post-quantum, a solid fill means a secret,
 * red means the attacker holds it. Same grammar as the rest of the site.
 */

/** A key: outline for public, filled for private, dotted ring for post-quantum. */
function Key({ x, y, solid, pq, hostile }: { x: number; y: number; solid?: boolean; pq?: boolean; hostile?: boolean }) {
  const stroke = hostile ? 'var(--k-attacker)' : 'var(--k-session)';
  return (
    <g transform={`translate(${x} ${y})`} className={pq ? 'g-pq' : ''}>
      <circle cx="0" cy="0" r="6" fill={solid ? stroke : 'var(--paper)'} stroke={stroke} strokeWidth="2" />
      <path d="M5 0h10m-4 0v4m4-4v3" stroke={stroke} strokeWidth="2" fill="none" strokeLinecap="round" />
      {pq && <circle cx="0" cy="0" r="9.5" fill="none" stroke={stroke} strokeWidth="1.3" strokeDasharray="1.5 2" />}
    </g>
  );
}

/** A padlock. Open reveals what it protected; dotted shackle = post-quantum. */
function Lock({ x, y, open, pq, tone = 'secret' }: { x: number; y: number; open?: boolean; pq?: boolean; tone?: 'secret' | 'good' | 'bad' }) {
  const body = tone === 'secret' ? 'var(--signal)' : tone === 'good' ? 'var(--good)' : 'var(--bad)';
  return (
    <g transform={`translate(${x} ${y})`}>
      <path d={open ? 'M-6-7a6 6 0 0 1 12 0' : 'M-6-3v-4a6 6 0 0 1 12 0v4'} fill="none" stroke="var(--ink)" strokeWidth="2" strokeDasharray={pq ? '2 2' : undefined} />
      <rect x="-8" y="-3" width="16" height="13" rx="2" fill={body} stroke="var(--ink)" strokeWidth="2" />
    </g>
  );
}

export type Step = 'kex' | 'cert' | 'token';

/** The diagram at the top of a process card: browser and server, and the thing this step makes. */
export function ProcessScene({ step, pq, live }: { step: Step; pq: boolean; live: boolean }) {
  return (
    <svg className={`scene ${live ? 'live' : 'ghost'}`} viewBox="0 0 240 92" role="img" aria-hidden="true">
      <g className="ends">
        <rect className="node" x="6" y="30" width="48" height="32" rx="4" />
        <text className="node-t" x="30" y="50">browser</text>
        <rect className="node" x="186" y="30" width="48" height="32" rx="4" />
        <text className="node-t" x="210" y="50">server</text>
      </g>
      {step === 'kex' && (
        <g>
          <path className="wire draw" d="M54 40H186" />
          <path className="wire draw d2" d="M186 52H54" />
          <g className="pop"><Key x={150} y={40} pq={false} /></g>
          <g className="pop d2"><Key x={74} y={52} pq={false} /></g>
          <g className="pop d3">
            <Lock x={120} y={40} pq={pq} />
            <text className="scene-tag" x="120" y="74">shared secret</text>
          </g>
        </g>
      )}
      {step === 'cert' && (
        <g>
          <path className="wire draw" d="M186 46H70" />
          {/* The position lives on an outer group: a CSS transform on the animated one would replace it. */}
          <g transform="translate(96 32)">
            <g className="pop d2">
              <rect className="card" x="0" y="0" width="48" height="30" rx="3" strokeDasharray={pq ? '3 2' : undefined} />
              <path className="sig" d="M7 10h22M7 16h30M7 22h16" />
            </g>
          </g>
          <g className="pop d3 check"><path d="M103 47l6 6 12-13" /></g>
          <text className="scene-tag" x="120" y="74">verified</text>
        </g>
      )}
      {step === 'token' && (
        <g>
          <g transform="translate(96 30)">
            <g className="pop">
              <rect className="card" x="0" y="0" width="48" height="30" rx="3" strokeDasharray={pq ? '3 2' : undefined} />
              <rect className="t-h" x="6" y="7" width="9" height="5" />
              <rect className="t-p" x="18" y="7" width="14" height="5" />
              <rect className="t-s" x="35" y="7" width="7" height="5" />
              <path className="sig" d="M7 19h34M7 24h20" />
            </g>
          </g>
          <path className="wire draw d2" d="M96 45H54" />
          <g className="pop d3 check"><path d="M150 42l6 6 12-13" /></g>
          <text className="scene-tag" x="168" y="74">signed by the site</text>
        </g>
      )}
    </svg>
  );
}

export type Phase = 'idle' | 'working' | 'won' | 'lost';
export type Job = 'recording' | 'site' | 'token';

/** The attacker's attempt at one job. The flow is the same for either computer; the ending differs. */
export function AttackScene({ job, phase, pq }: { job: Job; phase: Phase; pq: boolean }) {
  const won = phase === 'won';
  const lost = phase === 'lost';
  const working = phase === 'working';
  return (
    <svg className={`a-scene phase-${phase}`} viewBox="0 0 240 78" role="img" aria-hidden="true">
      {/* What she starts with: a copy she took off the wire. */}
      <g className="hostile-src">
        <rect className="box" x="8" y="24" width="40" height="30" rx="3" />
        <path className="box-hatch" d="M8 24h40v30H8z" />
      </g>
      {/* The work: a dish of churning, then a key she either gets or does not. */}
      <g className="work">
        <circle className="ring r1" cx="120" cy="39" r="22" />
        <circle className="ring r2" cx="120" cy="39" r="15" />
        {working && <circle className="spark" cx="120" cy="17" r="3" />}
        {won && <g className="got"><Key x={112} y={39} solid pq={false} hostile /></g>}
        {lost && <g className="nope"><path d="M110 29l20 20m0-20l-20 20" /></g>}
      </g>
      {/* The result she produces. */}
      <g className="out">
        {job === 'recording' && <Lock x={210} y={39} open={won} tone={won ? 'bad' : 'good'} pq={pq} />}
        {job !== 'recording' && (
          <g transform="translate(190 24)">
            <rect className={`card ${won ? 'forged' : 'held'}`} x="0" y="0" width="40" height="30" rx="3" />
            {won ? <path className="stamp-bad" d="M8 15h24" /> : <path className="stamp-ok" d="M8 15l6 6 18-14" />}
          </g>
        )}
      </g>
      <path className={`flow ${won ? 'won' : ''}`} d="M48 39H98M142 39H190" />
    </svg>
  );
}
