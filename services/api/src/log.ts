/**
 * Structured logs: one JSON object per line, with the request ID and scan ID
 * on every line that has them, so one scan can be followed across the API and
 * the worker.
 *
 * Values under keys that look like credentials are replaced before anything
 * is written. That is a net, not the mechanism: the code that handles tokens,
 * cookies and secrets does not pass them to the logger in the first place.
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Record<string, unknown>;

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  /** A logger that adds `fields` to every line. */
  child(fields: LogFields): Logger;
}

const ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const SENSITIVE = /token|secret|password|cookie|authorization|verifier|csrf|session/i;

function redact(value: unknown, depth = 0): unknown {
  if (value instanceof Error) return { name: value.name, message: value.message, code: (value as { code?: unknown }).code };
  if (depth > 4 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1));
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, SENSITIVE.test(key) ? '[redacted]' : redact(item, depth + 1)]));
}

export function createLogger(options: { service: string; level?: LogLevel; write?: (line: string) => void }, bound: LogFields = {}): Logger {
  const threshold = ORDER[options.level ?? 'info'];
  const write = options.write ?? ((line: string) => process.stdout.write(`${line}\n`));
  const emit = (level: LogLevel, message: string, fields?: LogFields) => {
    if (ORDER[level] < threshold) return;
    write(JSON.stringify({ time: new Date().toISOString(), level, service: options.service, message, ...(redact({ ...bound, ...fields }) as LogFields) }));
  };
  return {
    debug: (message, fields) => emit('debug', message, fields),
    info: (message, fields) => emit('info', message, fields),
    warn: (message, fields) => emit('warn', message, fields),
    error: (message, fields) => emit('error', message, fields),
    child: (fields) => createLogger(options, { ...bound, ...fields }),
  };
}
