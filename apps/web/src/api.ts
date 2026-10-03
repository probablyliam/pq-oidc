/**
 * The web app's side of the scan service. One call: POST the address, read
 * the progress as it streams back, get the finished scan at the end. Nothing
 * is stored anywhere; the result lives in the page that asked for it.
 */
import type { ScanReport } from '@pq-oidc/scan-core/report';

export interface Meta {
  service: string;
  engine: string;
  /** Local test servers this deployment is allowed to scan. */
  labOrigins: string[];
  allowedPorts: number[];
}

export interface IssuerKeysResult {
  kind: 'issuer-keys';
  issuer: string;
  found: boolean;
  discoveryUrl?: string;
  declaredIssuer?: string;
  issuerMatches?: boolean;
  jwksUri?: string;
  jwks?: { keys?: unknown[] };
  error?: string;
}

export interface Scan {
  kind: 'scan' | 'issuer-keys';
  target: string;
  targetUrl: string;
  status: 'succeeded' | 'failed';
  createdAt: string;
  finishedAt: string;
  error?: { code: string; message: string };
  report?: ScanReport | IssuerKeysResult;
}

/** An error the service explained. `code` is stable; `message` is written for the person using the app. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

const NO_ANSWER = new ApiError(0, 'network', 'The scan service did not answer. Check your connection and try again.');

async function errorFrom(response: Response): Promise<ApiError> {
  const data = (await response.json().catch(() => undefined)) as { error?: { code?: string; message?: string } } | undefined;
  return new ApiError(response.status, data?.error?.code ?? 'error', data?.error?.message ?? `The scan service answered with an error (${response.status}).`);
}

export const api = {
  /** Null when there is no scan service behind this page. */
  async meta(): Promise<Meta | null> {
    try {
      const response = await fetch('/api/v1/meta', { credentials: 'omit' });
      if (!response.ok) return null;
      const meta = (await response.json()) as Meta;
      return meta?.service === 'pq-oidc' ? meta : null;
    } catch {
      return null;
    }
  },

  /**
   * Runs one scan. The service streams a line per step as it works, then the finished scan;
   * a refusal (a bad address, a limit) arrives before anything starts and is thrown as an ApiError.
   */
  async scan(target: string, kind: Scan['kind'] = 'scan', onProgress: (step: string) => void = () => {}, signal?: AbortSignal): Promise<Scan> {
    let response: Response;
    try {
      response = await fetch('/api/v1/scan', {
        method: 'POST',
        credentials: 'omit',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ target, kind }),
        signal,
      });
    } catch (error) {
      if (signal?.aborted) throw error;
      throw NO_ANSWER;
    }
    if (!response.ok) throw await errorFrom(response);
    // A repeat of a recent address is answered at once, as plain JSON.
    if (response.headers.get('content-type')?.startsWith('application/json')) return ((await response.json()) as { scan: Scan }).scan;

    const reader = response.body?.getReader();
    if (!reader) throw NO_ANSWER;
    const decoder = new TextDecoder();
    let buffered = '';
    let finished: Scan | undefined;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffered += decoder.decode(value, { stream: true });
      const lines = buffered.split('\n');
      buffered = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim()) continue;
        const event = JSON.parse(line) as { progress?: string; scan?: Scan };
        if (event.progress) onProgress(event.progress);
        if (event.scan) finished = event.scan;
      }
    }
    if (!finished) throw new ApiError(0, 'incomplete', 'The scan was cut short. Try again.');
    return finished;
  },
};
