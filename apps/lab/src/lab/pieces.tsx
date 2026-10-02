import type { Authenticity, Layer, ObjectKind, Operation, Thing } from './events.ts';

/**
 * The visual vocabulary of the lab. Each kind of object has one drawing and
 * one colour everywhere on the page:
 *   private key   green, solid, marked as staying put
 *   public key    blue outline, openly visible
 *   shared secret yellow, identical on both sides
 *   encrypted     dark, hatched, locked
 *   signature     bars attached to what was signed
 */
const ICONS: Record<ObjectKind, string> = {
  'private-key': 'M9 12a4 4 0 1 0-8 0 4 4 0 0 0 8 0Zm0 0h13m-4 0v4m4-4v3',
  'public-key': 'M9 12a4 4 0 1 0-8 0 4 4 0 0 0 8 0Zm0 0h13m-4 0v4m4-4v3',
  'key-share': 'M4 12h16M14 6l6 6-6 6',
  'shared-secret': 'M8 12a4 4 0 1 0 8 0 4 4 0 0 0-8 0ZM2 12h6m8 0h6',
  signature: 'M3 18V8m4 10V4m4 14v-8m4 8V6m4 12v-6',
  encrypted: 'M6 11V8a6 6 0 0 1 12 0v3M4 11h16v10H4z',
  token: 'M3 5h18v14H3zM7 15v-3m4 3V9m4 6v-4',
  data: 'M5 3h10l4 4v14H5zM9 11h6M9 15h6',
  nothing: 'M6 6l12 12M18 6 6 18',
};

export function ThingView({ thing }: { thing: Thing }) {
  return (
    <span className={`thing ${thing.kind} ${thing.hostile ? 'hostile' : ''}`}>
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d={ICONS[thing.kind]} />
      </svg>
      <span>
        <b>{thing.label}</b>
        {thing.value && <small>{thing.value}</small>}
      </span>
    </span>
  );
}

const VERBS: Record<Operation['verb'], string> = {
  derive: 'Derive',
  sign: 'Sign',
  verify: 'Verify',
  encrypt: 'Encrypt',
  decrypt: 'Decrypt',
  check: 'Decrypt + check',
  recover: 'Attack',
};

/** inputs → [VERB] → output, with a tick or cross when the operation can fail. */
export function OperationView({ operation }: { operation: Operation }) {
  const failed = operation.ok === false;
  return (
    <div className={`operation ${operation.verb} ${failed ? 'failed' : operation.ok ? 'passed' : ''}`}>
      <div className="op-inputs">
        {operation.inputs.map((input, i) => (
          <ThingView key={i} thing={input} />
        ))}
      </div>
      <span className="op-verb">{VERBS[operation.verb]}</span>
      <div className="op-output">
        <ThingView thing={operation.output} />
        {operation.ok !== undefined && <span className="op-result">{operation.ok ? '✓' : '✕'}</span>}
      </div>
    </div>
  );
}

const AUTHENTICITY: Record<Authenticity, string> = {
  real: 'Real: this operation actually ran in your browser',
  representative: 'Simplified: a sketch of a real protocol step',
  conceptual: 'Conceptual: a future quantum attack, not something that can be run today',
};

export function AuthenticityTag({ value }: { value: Authenticity }) {
  return <span className={`authenticity ${value}`}>{AUTHENTICITY[value]}</span>;
}

const LAYERS: { id: Layer; name: string; parts: string }[] = [
  { id: 'request', name: 'Login request', parts: 'username and password' },
  { id: 'connection', name: 'Secure connection (HTTPS)', parts: 'key agreement, encryption, proving the server’s identity' },
  { id: 'login', name: 'The login itself', parts: 'password check, login token, token signature' },
];

/** A login is several layers, not one operation. This shows which layer the current step belongs to. */
export function LayerStack({ active }: { active: Layer | undefined }) {
  return (
    <ol className="layers" aria-label="Layers of a login">
      {LAYERS.map((layer) => (
        <li key={layer.id} aria-current={layer.id === active ? 'true' : undefined}>
          <b>{layer.name}</b>
          <span>{layer.parts}</span>
        </li>
      ))}
    </ol>
  );
}
