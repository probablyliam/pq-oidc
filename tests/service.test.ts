import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApi, createLogger, Store } from '@pq-oidc/api';
import type { ApiConfig } from '@pq-oidc/api';
import { createProviderApp, generateSigningKeys } from '@pq-oidc/provider';
import type { ScanReport } from '@pq-oidc/scan-core';
import { labProfile, startLabServer } from '@pq-oidc/scan-core/testing';
import type { LabServer } from '@pq-oidc/scan-core/testing';
import { analyzeToken, checkSignature } from '@pq-oidc/token-kit';
import { startWorker } from '@pq-oidc/worker';
import { TestBrowser } from './support/browser.ts';

/**
 * The service as a whole: the real OIDC provider, the API on its two ports,
 * a real worker and a lab TLS server, all in this process on random ports.
 */
const CLIENT_SECRET = 'test-client-secret-never-logged';
const WORKER_TOKEN = 'test-worker-token-never-logged-0123456789';
const LEASE_MS = 30_000;

interface Service {
  publicUrl: string;
  internalUrl: string;
  issuer: string;
  store: Store;
  logs: string[];
  /** Moves the API's clock forward (sessions, leases, rate-limit windows). */
  advance: (ms: number) => void;
  close: () => Promise<void>;
}

async function listen(): Promise<{ server: Server; url: string }> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

async function startService(overrides: { limits?: Partial<ApiConfig['limits']>; labOrigins?: string[]; webDir?: string } = {}): Promise<Service> {
  const [provider, api, internal] = await Promise.all([listen(), listen(), listen()]);
  const providerApp = createProviderApp({
    issuer: provider.url,
    jwks: await generateSigningKeys(),
    clients: [
      { clientId: 'scanner-web', clientSecret: CLIENT_SECRET, name: 'Scanner', redirectUri: `${api.url}/auth/callback`, postLogoutRedirectUri: `${api.url}/`, idTokenAlg: 'ML-DSA-65' },
    ],
  });
  provider.server.on('request', providerApp.handler);

  const logs: string[] = [];
  let skew = 0;
  const store = new Store({ path: ':memory:', leaseMs: LEASE_MS });
  const config: ApiConfig = {
    publicUrl: api.url,
    oidc: { issuer: provider.url, clientId: 'scanner-web', clientSecret: CLIENT_SECRET, idTokenAlgs: ['ML-DSA-65', 'ES256'] },
    workerToken: WORKER_TOKEN,
    databasePath: ':memory:',
    policy: { allowedPorts: [443, 8443], labOrigins: overrides.labOrigins ?? [] },
    limits: { scansPerWindow: 50, windowMs: 600_000, activePerUser: 50, perHostPerMinute: 50, maxQueueDepth: 100, ...overrides.limits },
    sessionTtlMs: 8 * 3_600_000,
    webDir: overrides.webDir,
  };
  const app = createApi({ config, store, log: createLogger({ service: 'api', level: 'debug', write: (line) => logs.push(line) }), now: () => Date.now() + skew });
  api.server.on('request', app.handler);
  internal.server.on('request', app.internalHandler);

  return {
    publicUrl: api.url,
    internalUrl: internal.url,
    issuer: provider.url,
    store,
    logs,
    advance: (ms) => (skew += ms),
    close: async () => {
      app.close();
      await Promise.all(
        [provider, api, internal].map(({ server }) => {
          server.closeAllConnections();
          return new Promise<void>((resolve) => server.close(() => resolve()));
        }),
      );
      store.close();
    },
  };
}

/** A signed-in browser, and a way to call the API as it. */
class Client {
  readonly browser = new TestBrowser();
  csrfToken = '';
  private readonly service: Service;

  constructor(service: Service) {
    this.service = service;
  }

  get sessionCookie(): string | undefined {
    return this.browser.cookie('127.0.0.1', 'pq_session');
  }

  async signIn(username: string, returnTo?: string) {
    const start = `${this.service.publicUrl}/auth/login${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ''}`;
    const loginPage = await this.browser.navigate(start);
    const landed = await this.browser.submitLogin(loginPage, username, 'quantum-safe');
    const session = await this.get('/api/v1/session');
    this.csrfToken = ((await session.json()) as { csrfToken?: string }).csrfToken ?? '';
    return landed;
  }

  private cookieHeader(): Record<string, string> {
    return this.sessionCookie ? { cookie: `pq_session=${this.sessionCookie}` } : {};
  }

  get(path: string) {
    return fetch(`${this.service.publicUrl}${path}`, { headers: this.cookieHeader() });
  }

  send(method: 'POST' | 'DELETE', path: string, body?: unknown, headers: Record<string, string> = {}) {
    return fetch(`${this.service.publicUrl}${path}`, {
      method,
      headers: { ...this.cookieHeader(), 'content-type': 'application/json', 'x-csrf-token': this.csrfToken, ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  async createScan(target: string, kind?: string): Promise<{ status: number; id: string; body: { error?: { code: string }; scan?: { id: string } } }> {
    const response = await this.send('POST', '/api/v1/scans', { target, kind });
    const body = (await response.json()) as { error?: { code: string }; scan?: { id: string } };
    return { status: response.status, id: body.scan?.id ?? '', body };
  }
}

const worker = (service: Service, path: string, body: unknown, token = WORKER_TOKEN) =>
  fetch(`${service.internalUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify(body) });

const errorCode = async (response: Response) => ((await response.json()) as { error: { code: string } }).error.code;

let service: Service;
let alice: Client;
let bob: Client;

beforeAll(async () => {
  service = await startService();
  alice = new Client(service);
  bob = new Client(service);
  await alice.signIn('alice');
  await bob.signIn('bob');
});
afterAll(() => service.close());

describe('sign-in', () => {
  it('creates a session for the user the provider vouched for', async () => {
    const session = (await (await alice.get('/api/v1/session')).json()) as { user: { name: string; email: string; sub: string } };
    expect(session.user).toEqual({ name: 'Alice Nakamura', email: 'alice.nakamura@example.com', sub: 'alice' });
  });

  it('receives an ML-DSA-65 ID token that verifies against the provider’s published keys', async () => {
    const { idToken } = (await (await alice.get('/api/v1/session/id-token')).json()) as { idToken: string };
    const analysis = analyzeToken(idToken);
    expect(analysis.alg).toMatchObject({ alg: 'ML-DSA-65', quantum: 'no-known-attack' });
    expect(analysis.payload).toMatchObject({ iss: service.issuer, aud: 'scanner-web', sub: 'alice' });
    const jwks = (await (await fetch(`${service.issuer}/jwks`)).json()) as { keys: unknown[] };
    expect(await checkSignature(idToken, jwks)).toMatchObject({ status: 'valid', key: { strength: 'ML-DSA-65' } });
  });

  it('keeps tokens out of the browser: the only cookie is an opaque, HttpOnly session ID', async () => {
    const fresh = new TestBrowser();
    const loginPage = await fresh.navigate(`${service.publicUrl}/auth/login`, { stopWhen: (url) => url.pathname === '/auth/callback' });
    const back = await fresh.submitLogin(loginPage, 'alice', 'quantum-safe', { stopWhen: (url) => url.pathname === '/auth/callback' });
    const response = await fetch(back.url, { redirect: 'manual', headers: { cookie: `pq_login=${fresh.cookie('127.0.0.1', 'pq_login')}` } });
    const session = response.headers.getSetCookie().find((c) => c.startsWith('pq_session='))!;
    expect(session).toMatch(/; HttpOnly/);
    expect(session).toMatch(/; SameSite=Lax/);
    expect(session.split(';')[0]!.length).toBeLessThan(80); // a random ID, not a token
    expect(response.headers.getSetCookie().join('\n')).not.toContain('eyJ');
  });

  it('cannot be finished twice, or without the browser that started it', async () => {
    const fresh = new TestBrowser();
    const stop = (url: URL) => url.pathname === '/auth/callback';
    const loginPage = await fresh.navigate(`${service.publicUrl}/auth/login`, { stopWhen: stop });
    const back = await fresh.submitLogin(loginPage, 'alice', 'quantum-safe', { stopWhen: stop });
    const withCookie = { redirect: 'manual' as const, headers: { cookie: `pq_login=${fresh.cookie('127.0.0.1', 'pq_login')}` } };

    // Someone who steals the callback URL but not the cookie gets nothing.
    const stolen = await fetch(back.url, { redirect: 'manual' });
    expect(stolen.headers.get('location')).toBe('/?signin_error=expired');
    expect(stolen.headers.getSetCookie().some((c) => c.startsWith('pq_session=') && !c.includes('Max-Age=0'))).toBe(false);

    const first = await fetch(back.url, withCookie);
    expect(first.headers.get('location')).toBe('/');
    const replay = await fetch(back.url, withCookie);
    expect(replay.headers.get('location')).toBe('/?signin_error=expired');
  });

  it('rejects a callback whose state does not match', async () => {
    const fresh = new TestBrowser();
    const stop = (url: URL) => url.pathname === '/auth/callback';
    const loginPage = await fresh.navigate(`${service.publicUrl}/auth/login`, { stopWhen: stop });
    const back = new URL((await fresh.submitLogin(loginPage, 'alice', 'quantum-safe', { stopWhen: stop })).url);
    back.searchParams.set('state', 'attacker-chosen');
    const response = await fetch(back, { redirect: 'manual', headers: { cookie: `pq_login=${fresh.cookie('127.0.0.1', 'pq_login')}` } });
    expect(response.headers.get('location')).toMatch(/^\/\?signin_error=/);
    expect(response.headers.getSetCookie().join('\n')).not.toMatch(/pq_session=[^;]/);
  });

  it.each(['//evil.example/', '/\\evil.example', 'https://evil.example/', 'javascript:alert(1)'])('does not redirect to %s after sign-in', async (returnTo) => {
    const carol = new Client(service);
    const landed = await carol.signIn('alice', returnTo);
    expect(new URL(landed.url).origin).toBe(service.publicUrl);
    expect(new URL(landed.url).pathname).toBe('/');
  });

  it('returns to a same-site path', async () => {
    const carol = new Client(service);
    const landed = await carol.signIn('alice', '/#/scans/abc');
    expect(landed.url).toBe(`${service.publicUrl}/#/scans/abc`);
  });

  it('ends the session on logout, and offers the provider’s logout URL', async () => {
    const carol = new Client(service);
    await carol.signIn('alice');
    expect((await carol.send('POST', '/auth/logout', {}, { 'x-csrf-token': '' })).status).toBe(403);
    const response = await carol.send('POST', '/auth/logout', {});
    expect(response.status).toBe(200);
    const { endSessionUrl } = (await response.json()) as { endSessionUrl: string };
    expect(endSessionUrl).toContain(`${service.issuer}/session/end`);
    expect(endSessionUrl).toContain('post_logout_redirect_uri=');
    expect((await carol.get('/api/v1/session')).status).toBe(401);
  });

  it('expires sessions', async () => {
    const other = await startService();
    try {
      const dave = new Client(other);
      await dave.signIn('alice');
      expect((await dave.get('/api/v1/scans')).status).toBe(200);
      other.advance(8 * 3_600_000 + 1000);
      expect((await dave.get('/api/v1/scans')).status).toBe(401);
    } finally {
      await other.close();
    }
  });
});

describe('every API route requires a session', () => {
  it.each([
    ['GET', '/api/v1/scans'],
    ['GET', '/api/v1/scans/00000000-0000-4000-8000-000000000000'],
    ['GET', '/api/v1/session'],
    ['GET', '/api/v1/session/id-token'],
    ['POST', '/api/v1/scans'],
    ['DELETE', '/api/v1/scans/00000000-0000-4000-8000-000000000000'],
    ['POST', '/auth/logout'],
  ])('%s %s without a session is 401', async (method, path) => {
    const response = await fetch(`${service.publicUrl}${path}`, { method, headers: { 'content-type': 'application/json' }, body: method === 'GET' ? undefined : '{}' });
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe('unauthenticated');
  });

  it('treats a made-up session cookie as no session', async () => {
    const response = await fetch(`${service.publicUrl}/api/v1/scans`, { headers: { cookie: 'pq_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } });
    expect(response.status).toBe(401);
  });

  it('serves only public information without one', async () => {
    const meta = (await (await fetch(`${service.publicUrl}/api/v1/meta`)).json()) as Record<string, unknown>;
    expect(meta).toMatchObject({ service: 'pq-oidc', signInUrl: '/auth/login' });
    expect(JSON.stringify(meta)).not.toMatch(/secret|token/i);
  });
});

describe('a user sees only their own scans', () => {
  let scanId: string;
  beforeAll(async () => {
    scanId = (await alice.createScan('https://example.com/login')).id;
  });

  it('the owner can read it', async () => {
    const response = await alice.get(`/api/v1/scans/${scanId}`);
    expect(response.status).toBe(200);
    expect(((await response.json()) as { scan: { target: string; status: string } }).scan).toMatchObject({ target: 'https://example.com/login', status: 'queued' });
  });

  it('another user gets the same answer as for a scan that does not exist', async () => {
    const theirs = await bob.get(`/api/v1/scans/${scanId}`);
    const missing = await bob.get('/api/v1/scans/00000000-0000-4000-8000-000000000000');
    expect(theirs.status).toBe(404);
    expect(await theirs.json()).toEqual({ error: { ...((await missing.json()) as { error: object }).error, requestId: expect.any(String) } });
  });

  it('another user cannot delete it, and does not see it listed', async () => {
    expect((await bob.send('DELETE', `/api/v1/scans/${scanId}`)).status).toBe(404);
    const list = (await (await bob.get('/api/v1/scans')).json()) as { scans: { id: string }[] };
    expect(list.scans.map((s) => s.id)).not.toContain(scanId);
    expect((await alice.get(`/api/v1/scans/${scanId}`)).status).toBe(200);
  });

  it('the owner can delete it', async () => {
    const mine = (await alice.createScan('https://example.org/')).id;
    expect((await alice.send('DELETE', `/api/v1/scans/${mine}`)).status).toBe(204);
    expect((await alice.get(`/api/v1/scans/${mine}`)).status).toBe(404);
  });
});

describe('cross-site requests are refused', () => {
  const body = { target: 'https://example.net/' };

  it.each([
    ['no CSRF token', { 'x-csrf-token': '' }],
    ['another session’s CSRF token', {}], // filled in below
    ['an Origin header from another site', { origin: 'https://evil.example' }],
    ['Sec-Fetch-Site: cross-site', { 'sec-fetch-site': 'cross-site' }],
  ])('with %s', async (what, headers) => {
    const response = await alice.send('POST', '/api/v1/scans', body, what.startsWith('another') ? { 'x-csrf-token': bob.csrfToken } : (headers as Record<string, string>));
    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe('csrf');
  });

  it('with a form body, which is what a cross-site form can send', async () => {
    const response = await fetch(`${service.publicUrl}/api/v1/scans`, {
      method: 'POST',
      headers: { cookie: `pq_session=${alice.sessionCookie}`, 'content-type': 'application/x-www-form-urlencoded', 'x-csrf-token': alice.csrfToken },
      body: 'target=https://example.net/',
    });
    expect(response.status).toBe(415);
  });

  it('accepts the same request from the application itself', async () => {
    const response = await alice.send('POST', '/api/v1/scans', body, { origin: service.publicUrl, 'sec-fetch-site': 'same-origin' });
    expect(response.status).toBe(202);
  });
});

describe('targets are checked before anything is queued', () => {
  it.each([
    ['https://127.0.0.1/', 'address-not-allowed'],
    ['https://169.254.169.254/latest/meta-data/', 'address-not-allowed'],
    ['https://[::ffff:10.0.0.1]/', 'address-not-allowed'],
    ['https://2130706433/', 'address-not-allowed'],
    ['https://localhost/', 'hostname-not-allowed'],
    ['https://kubernetes.default.svc/', 'hostname-not-allowed'],
    ['http://example.com/', 'scheme-not-allowed'],
    ['https://example.com:22/', 'port-not-allowed'],
    ['https://user:pass@example.com/', 'credentials-in-url'],
  ])('%s is refused as %s', async (target, code) => {
    const before = service.store.queueDepth();
    const result = await alice.createScan(target);
    expect(result.status).toBe(422);
    expect(result.body.error?.code).toBe(code);
    expect(service.store.queueDepth()).toBe(before);
  });

  it('needs a target', async () => {
    expect((await alice.send('POST', '/api/v1/scans', {})).status).toBe(400);
    expect((await alice.send('POST', '/api/v1/scans', { target: 42 })).status).toBe(400);
  });

  it('refuses an oversized body', async () => {
    const response = await alice.send('POST', '/api/v1/scans', { target: 'https://example.com/', padding: 'x'.repeat(20_000) });
    expect(response.status).toBe(413);
  });
});

describe('rate limits', () => {
  it('limits how many scans a user can start per window', async () => {
    const limited = await startService({ limits: { scansPerWindow: 3 } });
    try {
      const erin = new Client(limited);
      await erin.signIn('alice');
      for (let i = 0; i < 3; i++) expect((await erin.createScan(`https://site-${i}.example.com/`)).status).toBe(202);
      const fourth = await erin.send('POST', '/api/v1/scans', { target: 'https://site-4.example.com/' });
      expect(fourth.status).toBe(429);
      expect(fourth.headers.get('retry-after')).toBeTruthy();
      expect(await errorCode(fourth)).toBe('rate-limited');
      // The window moves on.
      limited.advance(601_000);
      expect((await erin.createScan('https://site-5.example.com/')).status).toBe(202);
    } finally {
      await limited.close();
    }
  });

  it('limits how many scans a user can have in progress', async () => {
    const limited = await startService({ limits: { activePerUser: 2 } });
    try {
      const erin = new Client(limited);
      await erin.signIn('alice');
      await erin.createScan('https://a.example.com/');
      await erin.createScan('https://b.example.com/');
      expect((await erin.createScan('https://c.example.com/')).body.error?.code).toBe('too-many-active');
    } finally {
      await limited.close();
    }
  });

  it('limits how often one host is scanned, whoever asks', async () => {
    const limited = await startService({ limits: { perHostPerMinute: 2 } });
    try {
      const [erin, frank] = [new Client(limited), new Client(limited)];
      await erin.signIn('alice');
      await frank.signIn('bob');
      expect((await erin.createScan('https://victim.example.com/a')).status).toBe(202);
      expect((await frank.createScan('https://victim.example.com/b')).status).toBe(202);
      expect((await erin.createScan('https://victim.example.com/c')).body.error?.code).toBe('host-busy');
      expect((await frank.createScan('https://VICTIM.example.com./d')).body.error?.code).toBe('host-busy');
      expect((await frank.createScan('https://other.example.com/')).status).toBe(202);
    } finally {
      await limited.close();
    }
  });
});

describe('the worker protocol', () => {
  let queue: Service;
  let owner: Client;
  beforeAll(async () => {
    queue = await startService();
    owner = new Client(queue);
    await owner.signIn('alice');
  });
  afterAll(() => queue.close());

  it('is not reachable without the worker token, or on the public port', async () => {
    expect((await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w1' }, 'wrong-token')).status).toBe(401);
    expect((await fetch(`${queue.internalUrl}/internal/v1/jobs/claim`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status).toBe(401);
    const onPublic = await fetch(`${queue.publicUrl}/internal/v1/jobs/claim`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${WORKER_TOKEN}` }, body: '{}' });
    expect(onPublic.status).toBe(404);
    expect((await fetch(`${queue.publicUrl}/metrics`)).status).toBe(404);
  });

  it('hands out a job, shows its progress to the owner, and stores the result', async () => {
    const { id } = await owner.createScan('https://example.com/');
    const claim = (await (await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w1' })).json()) as { job: { id: string; attempt: number; input: string } };
    expect(claim.job).toMatchObject({ id, attempt: 1, input: 'https://example.com/' });
    expect((await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w2' })).status).toBe(204); // nothing else queued

    expect((await worker(queue, `/internal/v1/jobs/${id}/progress`, { workerId: 'w1', step: 'TLS handshake' })).status).toBe(204);
    expect(((await (await owner.get(`/api/v1/scans/${id}`)).json()) as { scan: object }).scan).toMatchObject({ status: 'running', progress: 'TLS handshake' });

    // Another worker cannot report on a job it does not hold.
    expect((await worker(queue, `/internal/v1/jobs/${id}/result`, { workerId: 'w2', status: 'succeeded', result: { layers: [] } })).status).toBe(409);

    const report = { schema: 1, layers: [{ id: 'key-establishment', headline: 'Classical: x25519' }], findings: [] };
    expect((await worker(queue, `/internal/v1/jobs/${id}/result`, { workerId: 'w1', status: 'succeeded', result: report })).status).toBe(204);
    const scan = ((await (await owner.get(`/api/v1/scans/${id}`)).json()) as { scan: Record<string, unknown> }).scan;
    expect(scan).toMatchObject({ status: 'succeeded', report, layers: report.layers });
    expect(scan.progress).toBeUndefined();
  });

  it('retries a job whose worker went silent, once, then fails it', async () => {
    const { id } = await owner.createScan('https://example.org/');
    expect(((await (await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w1' })).json()) as { job: { attempt: number } }).job.attempt).toBe(1);

    queue.advance(LEASE_MS + 1000); // w1 never reports
    const second = (await (await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w2' })).json()) as { job: { id: string; attempt: number } };
    expect(second.job).toMatchObject({ id, attempt: 2 });
    // w1 comes back late: its lease is gone and its result is refused.
    expect((await worker(queue, `/internal/v1/jobs/${id}/result`, { workerId: 'w1', status: 'succeeded', result: { layers: [] } })).status).toBe(409);
    expect((await worker(queue, `/internal/v1/jobs/${id}/progress`, { workerId: 'w1', step: 'late' })).status).toBe(409);

    queue.advance(LEASE_MS + 1000); // w2 goes silent too
    expect((await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w3' })).status).toBe(204);
    const scan = ((await (await owner.get(`/api/v1/scans/${id}`)).json()) as { scan: { status: string; error: { code: string } } }).scan;
    expect(scan).toMatchObject({ status: 'failed', error: { code: 'worker-lost' } });
  });

  it('a heartbeat keeps the lease', async () => {
    const { id } = await owner.createScan('https://example.net/');
    await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w1' });
    queue.advance(LEASE_MS - 5000);
    expect((await worker(queue, `/internal/v1/jobs/${id}/progress`, { workerId: 'w1', step: 'still going' })).status).toBe(204);
    queue.advance(LEASE_MS - 5000);
    expect((await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w2' })).status).toBe(204);
    expect((await worker(queue, `/internal/v1/jobs/${id}/result`, { workerId: 'w1', status: 'failed', error: { code: 'dns-failure', message: 'Could not resolve example.net.' } })).status).toBe(204);
    const scan = ((await (await owner.get(`/api/v1/scans/${id}`)).json()) as { scan: object }).scan;
    expect(scan).toMatchObject({ status: 'failed', error: { code: 'dns-failure', message: 'Could not resolve example.net.' } });
  });

  it('exposes metrics on the internal port, labelled by route pattern rather than by scan ID', async () => {
    const text = await (await fetch(`${queue.internalUrl}/metrics`)).text();
    expect(text).toMatch(/scans_created_total\{kind="scan"\} \d+/);
    expect(text).toMatch(/scan_jobs\{status="succeeded"\} 1/);
    expect(text).toContain('route="/api/v1/scans/:id"');
    expect(text).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}/); // no scan IDs in labels
  });
});

describe('end to end: sign in, scan a lab server, read the report', () => {
  let lab: LabServer;
  let pqLab: LabServer;
  let full: Service;
  let user: Client;
  let stopWorker: () => Promise<void>;

  beforeAll(async () => {
    lab = await startLabServer(labProfile('hybrid'));
    pqLab = await startLabServer(labProfile('pq'));
    const labOrigins = [lab.origin, pqLab.origin];
    full = await startService({ labOrigins });
    user = new Client(full);
    await user.signIn('alice');
    const running = startWorker({
      apiUrl: full.internalUrl,
      token: WORKER_TOKEN,
      workerId: 'test-worker',
      policy: { allowedPorts: [443, 8443], labOrigins },
      pollMs: 50,
      // Everything resolves to an internal address except the lab: a public-looking name must still be refused.
      lookup: (hostname) => Promise.resolve([{ address: hostname === 'localhost' ? '127.0.0.1' : '10.0.0.7', family: 4 }]),
    });
    stopWorker = running.stop;
  }, 30_000);
  afterAll(async () => {
    await stopWorker();
    await Promise.all([lab.close(), pqLab.close(), full.close()]);
  });

  async function finished(id: string) {
    for (let i = 0; i < 300; i++) {
      const { scan } = (await (await user.get(`/api/v1/scans/${id}`)).json()) as { scan: { status: string; report?: ScanReport; error?: { code: string }; layers?: { headline: string }[] } };
      if (scan.status === 'succeeded' || scan.status === 'failed') return scan;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error('scan did not finish');
  }

  it('produces a real report', async () => {
    const { id, status } = await user.createScan(lab.origin);
    expect(status).toBe(202);
    const scan = await finished(id);
    expect(scan.status).toBe('succeeded');
    expect(scan.report?.layers[0]).toMatchObject({ id: 'key-establishment', headline: 'Hybrid: X25519MLKEM768, with classical fallback' });
    expect(scan.report?.findings.find((f) => f.id === 'kex.negotiated')?.kind).toBe('observation');

    const list = (await (await user.get('/api/v1/scans')).json()) as { scans: { id: string; layers: { headline: string }[]; report?: unknown }[] };
    expect(list.scans[0]).toMatchObject({ id, layers: expect.arrayContaining([expect.objectContaining({ headline: 'Classical: ECDSA P-256 certificate' })]) });
    expect(list.scans[0]!.report).toBeUndefined(); // list views carry summaries, not full reports
  });

  it('fails a scan whose target resolves to an internal address, with the reason', async () => {
    const { id } = await user.createScan('https://innocent.example.com/');
    const scan = await finished(id);
    expect(scan).toMatchObject({ status: 'failed', error: { code: 'address-not-allowed' } });
  });

  it('fetches an issuer’s public keys through the scanner, for a browser that could not', async () => {
    const { id } = await user.createScan(pqLab.origin, 'issuer-keys');
    const scan = (await finished(id)) as unknown as { status: string; report: { kind: string; found: boolean; jwks: { keys: { alg: string }[] } } };
    expect(scan.status).toBe('succeeded');
    expect(scan.report).toMatchObject({ kind: 'issuer-keys', found: true, issuerMatches: true });
    expect(scan.report.jwks.keys[0]!.alg).toBe('ML-DSA-65');
    // Key lookups are not listed as scans.
    const list = (await (await user.get('/api/v1/scans')).json()) as { scans: { id: string }[] };
    expect(list.scans.map((s) => s.id)).not.toContain(id);
  });
});

describe('secrets stay out of the logs', () => {
  it('logs none of the credentials that passed through these tests', async () => {
    const { idToken } = (await (await alice.get('/api/v1/session/id-token')).json()) as { idToken: string };
    const logs = service.logs.join('\n');
    expect(logs).toContain('signed in'); // the logger was in use
    for (const secret of [alice.sessionCookie!, alice.csrfToken, bob.sessionCookie!, CLIENT_SECRET, WORKER_TOKEN, idToken, idToken.split('.')[2]!.slice(0, 40)]) {
      expect(logs).not.toContain(secret);
    }
  });

  it('carries a request ID on every line, taken from the caller only when it is harmless', async () => {
    const good = await fetch(`${service.publicUrl}/api/v1/meta`, { headers: { 'x-request-id': 'trace-abc12345' } });
    expect(good.headers.get('x-request-id')).toBe('trace-abc12345');
    const bad = await fetch(`${service.publicUrl}/api/v1/meta`, { headers: { 'x-request-id': 'x"} injected {"level":"error' } });
    expect(bad.headers.get('x-request-id')).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('serving the web app', () => {
  let web: Service;
  beforeAll(async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pq-oidc-web-'));
    writeFileSync(join(dir, 'index.html'), '<!doctype html><title>app</title>');
    web = await startService({ webDir: dir });
  });
  afterAll(() => web.close());

  it('serves the page with a strict Content-Security-Policy', async () => {
    const response = await fetch(`${web.publicUrl}/`);
    expect(response.status).toBe(200);
    const csp = response.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe');
  });

  it.each(['/../package.json', '/..%2f..%2fpackage.json', '/%2e%2e/%2e%2e/package.json', '/....//....//package.json', '/%00', '/C:/Windows/win.ini'])(
    'does not serve files outside the web directory (%s)',
    async (path) => {
      // fetch() would normalise "..", so the request line is written by hand.
      const { port } = new URL(web.publicUrl);
      const net = await import('node:net');
      const status = await new Promise<number>((resolve) => {
        const socket = net.connect(Number(port), '127.0.0.1', () => socket.write(`GET ${path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`));
        socket.once('data', (data: Buffer) => {
          resolve(Number(data.toString().split(' ')[1]));
          socket.destroy();
        });
      });
      expect([400, 404]).toContain(status);
    },
  );
});
