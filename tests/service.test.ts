import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApi, createLogger, Store } from '@pq-oidc/api';
import type { ApiConfig } from '@pq-oidc/api';
import type { ScanReport } from '@pq-oidc/scan-core';
import { labProfile, startLabServer } from '@pq-oidc/scan-core/testing';
import type { LabServer } from '@pq-oidc/scan-core/testing';
import { startWorker } from '@pq-oidc/worker';

/**
 * The service as a whole: the API on its two ports, a real worker and a lab
 * TLS server, all in this process on random ports. There are no accounts, so
 * a "visitor" here is just an address.
 */
const WORKER_TOKEN = 'test-worker-token-never-logged-0123456789';
const LEASE_MS = 30_000;

interface Service {
  publicUrl: string;
  internalUrl: string;
  store: Store;
  logs: string[];
  purge: () => void;
  /** Moves the API's clock forward (leases, rate-limit windows, retention). */
  advance: (ms: number) => void;
  close: () => Promise<void>;
}

async function listen(): Promise<{ server: Server; url: string }> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

interface Overrides {
  limits?: Partial<ApiConfig['limits']>;
  labOrigins?: string[];
  webDir?: string;
  reuseMs?: number;
  databasePath?: string;
  trustProxy?: boolean;
}

async function startService(overrides: Overrides = {}): Promise<Service> {
  const [api, internal] = await Promise.all([listen(), listen()]);
  const logs: string[] = [];
  let skew = 0;
  const databasePath = overrides.databasePath ?? ':memory:';
  const store = new Store({ path: databasePath, leaseMs: LEASE_MS });
  const config: ApiConfig = {
    publicUrl: api.url,
    workerToken: WORKER_TOKEN,
    databasePath,
    policy: { allowedPorts: [443, 8443], labOrigins: overrides.labOrigins ?? [] },
    limits: { scansPerWindow: 50, windowMs: 600_000, activePerClient: 50, perHostPerMinute: 50, maxQueueDepth: 100, ...overrides.limits },
    reuseMs: overrides.reuseMs ?? 0,
    retentionMs: 3_600_000,
    webDir: overrides.webDir,
  };
  const app = createApi({
    config,
    store,
    log: createLogger({ service: 'api', level: 'debug', write: (line) => logs.push(line) }),
    now: () => Date.now() + skew,
    // Tests play several visitors from one machine by naming their address in X-Forwarded-For.
    trustProxy: overrides.trustProxy ?? true,
  });
  api.server.on('request', app.handler);
  internal.server.on('request', app.internalHandler);

  return {
    publicUrl: api.url,
    internalUrl: internal.url,
    store,
    logs,
    purge: app.purge,
    advance: (ms) => (skew += ms),
    close: async () => {
      app.close();
      await Promise.all(
        [api, internal].map(({ server }) => {
          server.closeAllConnections();
          return new Promise<void>((resolve) => server.close(() => resolve()));
        }),
      );
      store.close();
    },
  };
}

interface ScanBody {
  scan?: { id: string; status: string; target: string; progress?: string; report?: unknown; error?: { code: string; message: string } };
  reused?: boolean;
  error?: { code: string; message: string; requestId: string };
}

/** Someone using the service from one address. */
function visitor(service: Service, address: string) {
  return {
    async scan(target: unknown, extra: { kind?: string; headers?: Record<string, string> } = {}): Promise<{ status: number; body: ScanBody; headers: Headers }> {
      const response = await fetch(`${service.publicUrl}/api/v1/scans`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-forwarded-for': address, ...extra.headers },
        body: JSON.stringify({ target, kind: extra.kind }),
      });
      return { status: response.status, body: (await response.json()) as ScanBody, headers: response.headers };
    },
    async read(id: string): Promise<{ status: number; body: ScanBody }> {
      const response = await fetch(`${service.publicUrl}/api/v1/scans/${id}`, { headers: { 'x-forwarded-for': address } });
      return { status: response.status, body: (await response.json()) as ScanBody };
    },
  };
}

const worker = (service: Service, path: string, body: unknown, token = WORKER_TOKEN) =>
  fetch(`${service.internalUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify(body) });

let service: Service;
beforeAll(async () => {
  service = await startService();
});
afterAll(() => service.close());

describe('scanning needs no account', () => {
  it('anyone can start a scan and read its result by ID', async () => {
    const ana = visitor(service, '198.51.100.1');
    const started = await ana.scan('https://example.com/login');
    expect(started.status).toBe(202);
    expect(started.body.scan).toMatchObject({ status: 'queued', target: 'https://example.com/login' });
    expect(started.headers.get('location')).toBe(`/api/v1/scans/${started.body.scan!.id}`);
    expect((await ana.read(started.body.scan!.id)).body.scan?.status).toBe('queued');
  });

  it('a result is a link: someone else with the ID can read it, and nobody can guess one', async () => {
    const { body } = await visitor(service, '198.51.100.1').scan('https://example.org/');
    const id = body.scan!.id;
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/); // a random UUID: 122 bits
    expect((await visitor(service, '198.51.100.77').read(id)).status).toBe(200);
    expect((await visitor(service, '198.51.100.77').read('00000000-0000-4000-8000-000000000000')).status).toBe(404);
  });

  it('sets no cookies and has no sign-in, session or listing endpoints', async () => {
    const started = await visitor(service, '198.51.100.1').scan('https://example.net/');
    expect(started.headers.getSetCookie()).toEqual([]);
    for (const path of ['/auth/login', '/api/v1/session', '/api/v1/scans']) {
      const response = await fetch(`${service.publicUrl}${path}`);
      expect([404, 405], path).toContain(response.status);
      expect(response.headers.getSetCookie()).toEqual([]);
    }
  });

  it('says what it is and what it allows, and nothing secret', async () => {
    const meta = (await (await fetch(`${service.publicUrl}/api/v1/meta`)).json()) as Record<string, unknown>;
    expect(meta).toMatchObject({ service: 'pq-oidc', allowedPorts: [443, 8443], retentionHours: 1 });
    expect(JSON.stringify(meta)).not.toMatch(/secret|token/i);
  });
});

describe('a page on another site cannot start scans from a visitor’s browser', () => {
  const ana = () => visitor(service, '198.51.100.2');

  it.each([
    ['an Origin header from another site', { origin: 'https://evil.example' }],
    ['Sec-Fetch-Site: cross-site', { 'sec-fetch-site': 'cross-site' }],
    ['Sec-Fetch-Site: same-site (a sibling subdomain)', { 'sec-fetch-site': 'same-site' }],
  ])('refuses a request with %s', async (_what, headers) => {
    const result = await ana().scan('https://example.com/', { headers });
    expect(result.status).toBe(403);
    expect(result.body.error?.code).toBe('cross-site');
  });

  it('refuses a form body, which is what a cross-site form can send without asking', async () => {
    const response = await fetch(`${service.publicUrl}/api/v1/scans`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'target=https://example.com/' });
    expect(response.status).toBe(415);
  });

  it('accepts the application’s own requests, and scripts that send no browser headers', async () => {
    expect((await ana().scan('https://a.example.com/', { headers: { origin: service.publicUrl, 'sec-fetch-site': 'same-origin' } })).status).toBe(202);
    expect((await ana().scan('https://b.example.com/')).status).toBe(202);
  });

  it('sends no CORS headers, so another origin could not read an answer anyway', async () => {
    const response = await fetch(`${service.publicUrl}/api/v1/meta`, { headers: { origin: 'https://evil.example' } });
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
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
    const result = await visitor(service, '198.51.100.3').scan(target);
    expect(result.status).toBe(422);
    expect(result.body.error?.code).toBe(code);
    expect(service.store.queueDepth()).toBe(before);
  });

  it('needs a target, and refuses an oversized body', async () => {
    const ana = visitor(service, '198.51.100.3');
    expect((await ana.scan(undefined)).status).toBe(400);
    expect((await ana.scan(42)).status).toBe(400);
    const big = await fetch(`${service.publicUrl}/api/v1/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target: 'https://example.com/', padding: 'x'.repeat(20_000) }) });
    expect(big.status).toBe(413);
  });
});

describe('the streaming scan the web app uses', () => {
  it('streams each step as the worker reports it, then the finished scan, as newline-delimited JSON', async () => {
    const lab = await startLabServer(labProfile('hybrid'));
    const live = await startService({ labOrigins: [lab.origin] });
    const running = startWorker({ apiUrl: live.internalUrl, token: WORKER_TOKEN, workerId: 'stream-worker', policy: { allowedPorts: [443, 8443], labOrigins: [lab.origin] }, pollMs: 50 });
    try {
      const response = await fetch(`${live.publicUrl}/api/v1/scan`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: live.publicUrl },
        body: JSON.stringify({ target: lab.origin }),
      });
      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toBe('application/x-ndjson');
      const lines = (await response.text()).trim().split('\n').map((l) => JSON.parse(l) as { progress?: string; scan?: { status: string; report?: { reachable: boolean } } });
      // A lab scan finishes in tens of milliseconds, so how many steps are relayed depends on timing;
      // whatever comes before the result must be a step, and the result comes last, once.
      expect(lines.slice(0, -1).every((l) => typeof l.progress === 'string')).toBe(true);
      expect(lines.filter((l) => l.scan)).toHaveLength(1);
      expect(lines.at(-1)?.scan).toMatchObject({ status: 'succeeded', report: { reachable: true } });
      // The same checks guard it: a private address is refused before anything is queued.
      const refused = await fetch(`${live.publicUrl}/api/v1/scan`, { method: 'POST', headers: { 'content-type': 'application/json', origin: live.publicUrl }, body: JSON.stringify({ target: 'https://127.0.0.1/' }) });
      expect(refused.status).toBe(422);
    } finally {
      await running.stop();
      await Promise.all([lab.close(), live.close()]);
    }
  }, 60_000);
});

describe('limits, since there are no accounts to hold anyone to', () => {
  it('limits how many scans one address can start per window, without affecting anyone else', async () => {
    const limited = await startService({ limits: { scansPerWindow: 3 } });
    try {
      const [ana, ben] = [visitor(limited, '203.0.113.1'), visitor(limited, '203.0.113.2')];
      for (let i = 0; i < 3; i++) expect((await ana.scan(`https://site-${i}.example.com/`)).status).toBe(202);
      const fourth = await ana.scan('https://site-4.example.com/');
      expect(fourth.status).toBe(429);
      expect(fourth.body.error?.code).toBe('rate-limited');
      expect(fourth.headers.get('retry-after')).toBeTruthy();
      expect((await ben.scan('https://site-4.example.com/')).status).toBe(202);
      limited.advance(601_000); // the window moves on
      expect((await ana.scan('https://site-5.example.com/')).status).toBe(202);
    } finally {
      await limited.close();
    }
  });

  it('cannot be dodged by claiming to be someone else, unless the server is told a proxy sets that header', async () => {
    const direct = await startService({ limits: { scansPerWindow: 2 }, trustProxy: false });
    try {
      expect((await visitor(direct, '203.0.113.10').scan('https://a.example.com/')).status).toBe(202);
      expect((await visitor(direct, '203.0.113.11').scan('https://b.example.com/')).status).toBe(202);
      expect((await visitor(direct, '203.0.113.12').scan('https://c.example.com/')).body.error?.code).toBe('rate-limited');
    } finally {
      await direct.close();
    }
  });

  it('limits how many scans one address can have in progress', async () => {
    const limited = await startService({ limits: { activePerClient: 2 } });
    try {
      const ana = visitor(limited, '203.0.113.1');
      await ana.scan('https://a.example.com/');
      await ana.scan('https://b.example.com/');
      expect((await ana.scan('https://c.example.com/')).body.error?.code).toBe('too-many-active');
    } finally {
      await limited.close();
    }
  });

  it('limits how often one host is scanned, whoever asks, so the service cannot be used to hammer it', async () => {
    const limited = await startService({ limits: { perHostPerMinute: 2 } });
    try {
      const [ana, ben] = [visitor(limited, '203.0.113.1'), visitor(limited, '203.0.113.2')];
      expect((await ana.scan('https://victim.example.com/a')).status).toBe(202);
      expect((await ben.scan('https://victim.example.com/b')).status).toBe(202);
      expect((await ana.scan('https://victim.example.com/c')).body.error?.code).toBe('host-busy');
      expect((await ben.scan('https://VICTIM.example.com./d')).body.error?.code).toBe('host-busy');
      expect((await ben.scan('https://other.example.com/')).status).toBe(202);
      // The limit is per service: another port on the same name is a different thing to protect.
      expect((await ben.scan('https://victim.example.com:8443/')).status).toBe(202);
    } finally {
      await limited.close();
    }
  });

  it('answers a repeat of a recent scan with the result that already exists', async () => {
    const reusing = await startService({ reuseMs: 300_000, limits: { scansPerWindow: 2 } });
    try {
      const [ana, ben] = [visitor(reusing, '203.0.113.1'), visitor(reusing, '203.0.113.2')];
      const first = await ana.scan('https://example.com/login');
      const again = await ben.scan('https://EXAMPLE.com/login#top'); // the same address once normalised
      expect(again.status).toBe(200);
      expect(again.body).toMatchObject({ reused: true, scan: { id: first.body.scan!.id } });
      // Reused answers cost nothing against the limit: Ana can ask for it as often as she likes.
      for (let i = 0; i < 5; i++) expect((await ana.scan('https://example.com/login')).body.reused).toBe(true);
      expect((await ana.scan('https://example.com/other')).status).toBe(202);
      reusing.advance(301_000);
      expect((await ben.scan('https://example.com/login')).status).toBe(202);
    } finally {
      await reusing.close();
    }
  });

  it('does not reuse a scan that failed', async () => {
    const reusing = await startService({ reuseMs: 300_000 });
    try {
      const ana = visitor(reusing, '203.0.113.1');
      const { body } = await ana.scan('https://example.com/');
      await worker(reusing, '/internal/v1/jobs/claim', { workerId: 'w1' });
      await worker(reusing, `/internal/v1/jobs/${body.scan!.id}/result`, { workerId: 'w1', status: 'failed', error: { code: 'dns-failure', message: 'no such host' } });
      expect((await ana.scan('https://example.com/')).status).toBe(202);
    } finally {
      await reusing.close();
    }
  });
});

describe('what is kept, and for how long', () => {
  it('keeps a keyed hash of the visitor’s address, never the address', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'pq-oidc-db-')), 'scans.sqlite');
    const durable = await startService({ databasePath: path });
    try {
      await visitor(durable, '203.0.113.99').scan('https://example.com/');
      await visitor(durable, '203.0.113.99').scan('https://example.org/');
      await visitor(durable, '203.0.113.98').scan('https://example.net/');
      const rows = new DatabaseSync(path, { readOnly: true }).prepare('SELECT * FROM scans').all() as Record<string, unknown>[];
      expect(rows).toHaveLength(3);
      expect(JSON.stringify(rows)).not.toContain('203.0.113');
      const clients = rows.map((row) => String(row.client));
      expect(clients.every((c) => /^[0-9a-f]{32}$/.test(c))).toBe(true);
      expect(new Set(clients).size).toBe(2); // the same visitor hashes the same, different visitors differently
      expect(Object.keys(rows[0]!)).not.toContain('user_id');
    } finally {
      await durable.close();
    }
  });

  it('deletes results after an hour, and not before', async () => {
    const kept = await startService();
    try {
      const ana = visitor(kept, '203.0.113.1');
      const finished = (await ana.scan('https://example.com/')).body.scan!.id;
      await worker(kept, '/internal/v1/jobs/claim', { workerId: 'w1' });
      await worker(kept, `/internal/v1/jobs/${finished}/result`, { workerId: 'w1', status: 'succeeded', result: { schema: 1 } });
      kept.advance(55 * 60_000);
      kept.purge();
      expect((await ana.read(finished)).status).toBe(200);
      kept.advance(10 * 60_000);
      kept.purge();
      expect((await ana.read(finished)).status).toBe(404);
    } finally {
      await kept.close();
    }
  });
});

describe('the worker protocol', () => {
  let queue: Service;
  const owner = () => visitor(queue, '203.0.113.1');
  beforeAll(async () => {
    queue = await startService();
  });
  afterAll(() => queue.close());

  it('is not reachable without the worker token, or on the public port', async () => {
    expect((await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w1' }, 'wrong-token')).status).toBe(401);
    expect((await fetch(`${queue.internalUrl}/internal/v1/jobs/claim`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status).toBe(401);
    const onPublic = await fetch(`${queue.publicUrl}/internal/v1/jobs/claim`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${WORKER_TOKEN}` }, body: '{}' });
    expect(onPublic.status).toBe(404);
    expect((await fetch(`${queue.publicUrl}/metrics`)).status).toBe(404);
  });

  it('hands out a job, shows its progress, and stores the result', async () => {
    const id = (await owner().scan('https://example.com/')).body.scan!.id;
    const claim = (await (await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w1' })).json()) as { job: { id: string; attempt: number; input: string } };
    expect(claim.job).toMatchObject({ id, attempt: 1, input: 'https://example.com/' });
    expect((await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w2' })).status).toBe(204); // nothing else queued

    expect((await worker(queue, `/internal/v1/jobs/${id}/progress`, { workerId: 'w1', step: 'TLS handshake' })).status).toBe(204);
    expect((await owner().read(id)).body.scan).toMatchObject({ status: 'running', progress: 'TLS handshake' });

    // Another worker cannot report on a job it does not hold.
    expect((await worker(queue, `/internal/v1/jobs/${id}/result`, { workerId: 'w2', status: 'succeeded', result: { layers: [] } })).status).toBe(409);

    const report = { schema: 1, layers: [{ id: 'key-establishment', headline: 'Classical: x25519' }], findings: [] };
    expect((await worker(queue, `/internal/v1/jobs/${id}/result`, { workerId: 'w1', status: 'succeeded', result: report })).status).toBe(204);
    const scan = (await owner().read(id)).body.scan!;
    expect(scan).toMatchObject({ status: 'succeeded', report });
    expect(scan.progress).toBeUndefined();
  });

  it('retries a job whose worker went silent, once, then fails it', async () => {
    const id = (await owner().scan('https://example.org/')).body.scan!.id;
    expect(((await (await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w1' })).json()) as { job: { attempt: number } }).job.attempt).toBe(1);

    queue.advance(LEASE_MS + 1000); // w1 never reports
    const second = (await (await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w2' })).json()) as { job: { id: string; attempt: number } };
    expect(second.job).toMatchObject({ id, attempt: 2 });
    // w1 comes back late: its lease is gone and its result is refused.
    expect((await worker(queue, `/internal/v1/jobs/${id}/result`, { workerId: 'w1', status: 'succeeded', result: { layers: [] } })).status).toBe(409);
    expect((await worker(queue, `/internal/v1/jobs/${id}/progress`, { workerId: 'w1', step: 'late' })).status).toBe(409);

    queue.advance(LEASE_MS + 1000); // w2 goes silent too
    expect((await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w3' })).status).toBe(204);
    expect((await owner().read(id)).body.scan).toMatchObject({ status: 'failed', error: { code: 'worker-lost' } });
  });

  it('a heartbeat keeps the lease', async () => {
    const id = (await owner().scan('https://example.net/')).body.scan!.id;
    await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w1' });
    queue.advance(LEASE_MS - 5000);
    expect((await worker(queue, `/internal/v1/jobs/${id}/progress`, { workerId: 'w1', step: 'still going' })).status).toBe(204);
    queue.advance(LEASE_MS - 5000);
    expect((await worker(queue, '/internal/v1/jobs/claim', { workerId: 'w2' })).status).toBe(204);
    expect((await worker(queue, `/internal/v1/jobs/${id}/result`, { workerId: 'w1', status: 'failed', error: { code: 'dns-failure', message: 'Could not resolve example.net.' } })).status).toBe(204);
    expect((await owner().read(id)).body.scan).toMatchObject({ status: 'failed', error: { code: 'dns-failure', message: 'Could not resolve example.net.' } });
  });

  it('exposes metrics on the internal port, labelled by route pattern rather than by scan ID', async () => {
    const text = await (await fetch(`${queue.internalUrl}/metrics`)).text();
    expect(text).toMatch(/scans_created_total\{kind="scan"\} \d+/);
    expect(text).toMatch(/scan_jobs\{status="succeeded"\} 1/);
    expect(text).toContain('route="/api/v1/scans/:id"');
    expect(text).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}/); // no scan IDs in labels
  });
});

describe('end to end: scan a lab server through a real worker', () => {
  let lab: LabServer;
  let pqLab: LabServer;
  let full: Service;
  let stopWorker: () => Promise<void>;
  const ana = () => visitor(full, '203.0.113.1');

  beforeAll(async () => {
    lab = await startLabServer(labProfile('hybrid'));
    pqLab = await startLabServer(labProfile('pq'));
    const labOrigins = [lab.origin, pqLab.origin];
    full = await startService({ labOrigins });
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
      const scan = (await ana().read(id)).body.scan!;
      if (scan.status === 'succeeded' || scan.status === 'failed') return scan;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error('scan did not finish');
  }

  it('produces a real report', async () => {
    const started = await ana().scan(lab.origin);
    expect(started.status).toBe(202);
    const scan = await finished(started.body.scan!.id);
    expect(scan.status).toBe('succeeded');
    const report = scan.report as ScanReport;
    expect(report.layers[0]).toMatchObject({ id: 'key-establishment', headline: 'Hybrid: X25519MLKEM768, with classical fallback' });
    expect(report.findings.find((f) => f.id === 'kex.negotiated')?.kind).toBe('observation');
  });

  it('fails a scan whose target resolves to an internal address, with the reason', async () => {
    const scan = await finished((await ana().scan('https://innocent.example.com/')).body.scan!.id);
    expect(scan).toMatchObject({ status: 'failed', error: { code: 'address-not-allowed' } });
  });

  it('fetches an issuer’s public keys, for a browser that was not allowed to', async () => {
    const scan = await finished((await ana().scan(pqLab.origin, { kind: 'issuer-keys' })).body.scan!.id);
    expect(scan.status).toBe('succeeded');
    const result = scan.report as { kind: string; found: boolean; issuerMatches: boolean; jwks: { keys: { alg: string }[] } };
    expect(result).toMatchObject({ kind: 'issuer-keys', found: true, issuerMatches: true });
    expect(result.jwks.keys[0]!.alg).toBe('ML-DSA-65');
  });
});

describe('logs', () => {
  it('carry no worker token and no visitor address', async () => {
    await visitor(service, '198.51.100.250').scan('https://logged.example.com/');
    const logs = service.logs.join('\n');
    expect(logs).toContain('scan queued'); // the logger was in use
    expect(logs).toContain('logged.example.com');
    expect(logs).not.toContain(WORKER_TOKEN);
    expect(logs).not.toContain('198.51.100.250');
  });

  it('carry a request ID on every line, taken from the caller only when it is harmless', async () => {
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
