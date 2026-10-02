/** The web app's side of the API: start a scan, then read it by its ID until it finishes. */
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
  id: string;
  kind: 'scan' | 'issuer-keys';
  target: string;
  targetUrl: string;
  status: 'queued' | 'running' | 'succeeded' | 'failed';
  createdAt: string;
  finishedAt: string | null;
  progress?: string;
  error?: { code: string; message: string };
  report?: ScanReport | IssuerKeysResult;
}

/** An error the API explained. `code` is stable; `message` is written for the person using the app. */
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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      credentials: 'omit',
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'network', 'The scan service did not answer. Check your connection and try again.');
  }
  const data: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const error = (data as { error?: { code?: string; message?: string } } | undefined)?.error;
    throw new ApiError(response.status, error?.code ?? 'error', error?.message ?? `The scan service answered with an error (${response.status}).`);
  }
  return data as T;
}

export const api = {
  /** Null when there is no scan service behind this page. */
  async meta(): Promise<Meta | null> {
    try {
      // On a static host this path is a 404 page, not JSON, and that is the answer.
      const meta = await request<Meta>('GET', '/api/v1/meta');
      return meta?.service === 'pq-oidc' ? meta : null;
    } catch {
      return null;
    }
  },

  createScan: (target: string, kind: Scan['kind'] = 'scan') => request<{ scan: Scan }>('POST', '/api/v1/scans', { target, kind }).then((r) => r.scan),
  getScan: (id: string) => request<{ scan: Scan }>('GET', `/api/v1/scans/${encodeURIComponent(id)}`).then((r) => r.scan),

  /** Polls a job until it finishes, reporting each state on the way. */
  async waitForScan(id: string, onUpdate: (scan: Scan) => void, signal: AbortSignal): Promise<Scan> {
    for (;;) {
      const scan = await this.getScan(id);
      if (signal.aborted) return scan;
      onUpdate(scan);
      if (scan.status === 'succeeded' || scan.status === 'failed') return scan;
      await new Promise((resolve) => setTimeout(resolve, 500));
      if (signal.aborted) return scan;
    }
  },
};
