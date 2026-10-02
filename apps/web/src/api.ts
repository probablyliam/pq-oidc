/**
 * The web app's side of the API. The browser holds no tokens: requests carry
 * the session cookie, and anything that changes state also carries the
 * per-session CSRF token the API handed out with the session.
 */
import type { LayerSummary, ScanReport } from '@pq-oidc/scan-core/report';

export interface Meta {
  service: string;
  engine: string;
  signInUrl: string;
  /** Local test servers this deployment is allowed to scan. */
  labOrigins: string[];
  /** The issuer this deployment signs its users in with. */
  identityProvider: string;
  allowedPorts: number[];
}

export interface SessionInfo {
  user: { name: string | null; email: string | null; sub: string };
  expiresAt: string;
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
  layers?: LayerSummary[];
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

let csrfToken = '';

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: body === undefined && method === 'GET' ? {} : { 'content-type': 'application/json', 'x-csrf-token': csrfToken },
      body: body === undefined ? (method === 'GET' ? undefined : '{}') : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'network', 'The scan service did not answer. Check your connection and try again.');
  }
  if (response.status === 204) return undefined as T;
  const data: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const error = (data as { error?: { code?: string; message?: string } } | undefined)?.error;
    throw new ApiError(response.status, error?.code ?? 'error', error?.message ?? `The scan service answered with an error (${response.status}).`);
  }
  return data as T;
}

export const api = {
  /** Null when there is no scan service behind this page (the static build on GitHub Pages). */
  async meta(): Promise<Meta | null> {
    try {
      // On a static host this path is a 404 page, not JSON, and that is the answer.
      const meta = await request<Meta>('GET', '/api/v1/meta');
      return meta?.service === 'pq-oidc' ? meta : null;
    } catch {
      return null;
    }
  },

  /** Null when nobody is signed in. */
  async session(): Promise<SessionInfo | null> {
    const session = await request<{ user: SessionInfo['user'] | null; csrfToken?: string; expiresAt?: string }>('GET', '/api/v1/session');
    if (!session.user) return null;
    csrfToken = session.csrfToken ?? '';
    return { user: session.user, expiresAt: session.expiresAt ?? '' };
  },

  signInUrl(returnTo: string): string {
    return `/auth/login?return_to=${encodeURIComponent(returnTo)}`;
  },

  async signOut(): Promise<string | undefined> {
    const { endSessionUrl } = await request<{ endSessionUrl?: string }>('POST', '/auth/logout');
    csrfToken = '';
    return endSessionUrl;
  },

  createScan: (target: string, kind: Scan['kind'] = 'scan') => request<{ scan: Scan }>('POST', '/api/v1/scans', { target, kind }).then((r) => r.scan),
  getScan: (id: string) => request<{ scan: Scan }>('GET', `/api/v1/scans/${encodeURIComponent(id)}`).then((r) => r.scan),
  listScans: () => request<{ scans: Scan[] }>('GET', '/api/v1/scans?limit=50').then((r) => r.scans),
  deleteScan: (id: string) => request<void>('DELETE', `/api/v1/scans/${encodeURIComponent(id)}`),
  /** The ID token from this user's own sign-in. */
  idToken: () => request<{ idToken: string | null }>('GET', '/api/v1/session/id-token').then((r) => r.idToken),

  /** Polls a job until it finishes, reporting each state on the way. */
  async waitForScan(id: string, onUpdate: (scan: Scan) => void, signal: AbortSignal): Promise<Scan> {
    for (;;) {
      const scan = await this.getScan(id);
      onUpdate(scan);
      if (scan.status === 'succeeded' || scan.status === 'failed') return scan;
      await new Promise((resolve) => setTimeout(resolve, 600));
      if (signal.aborted) return scan;
    }
  },
};
