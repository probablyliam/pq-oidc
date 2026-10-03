import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { LAB_PROFILES, startLabServer } from '@pq-oidc/scan-core/testing';
import type { LabServer } from '@pq-oidc/scan-core/testing';
import handler, { LIMITS, memory } from './scan.ts';

/**
 * The Vercel function, called the way Vercel calls it: a Request in, a
 * Response out. Scans go to a lab server; the policy's lab-origin exception
 * is set for the duration of the test.
 */
let lab: LabServer;
const HOST = 'pq-oidc.example';

beforeAll(async () => {
  lab = await startLabServer(LAB_PROFILES.find((p) => p.id === 'hybrid')!);
  const { DEFAULT_POLICY } = await import('@pq-oidc/scan-core');
  (DEFAULT_POLICY as unknown as { labOrigins: string[] }).labOrigins = [lab.origin];
}, 30_000);
afterAll(() => lab.close());
beforeEach(() => memory.reset());

function post(body: unknown, headers: Record<string, string> = {}, ip = '203.0.113.7'): Request {
  return new Request(`https://${HOST}/api/v1/scan`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', host: HOST, origin: `https://${HOST}`, 'sec-fetch-site': 'same-origin', 'x-forwarded-for': ip, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

/** Reads a streamed response: the progress lines, and the final scan. */
async function read(response: Response) {
  const lines = (await response.text()).trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
  return { progress: lines.filter((l) => 'progress' in l).map((l) => l.progress as string), scan: lines.find((l) => 'scan' in l)?.scan as Record<string, unknown> | undefined };
}

describe('a scan through the function', () => {
  it('streams progress, then the finished scan, with no database anywhere', async () => {
    const response = await handler.fetch(post({ target: lab.origin }));
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/x-ndjson');
    const { progress, scan } = await read(response);
    expect(progress[0]).toMatch(/^Resolving/);
    expect(progress.some((p) => /TLS handshake/.test(p))).toBe(true);
    expect(scan).toMatchObject({ status: 'succeeded', kind: 'scan', target: lab.origin });
    const report = scan!.report as { reachable: boolean; layers: { id: string; headline: string }[] };
    expect(report.reachable).toBe(true);
    expect(report.layers.find((l) => l.id === 'key-establishment')!.headline).toMatch(/^Hybrid/);
  }, 30_000);

  it('answers a repeat of the same address from memory instead of scanning again', async () => {
    await read(await handler.fetch(post({ target: lab.origin })));
    const again = await handler.fetch(post({ target: lab.origin }));
    expect(again.headers.get('content-type')).toBe('application/json');
    expect(await again.json()).toMatchObject({ reused: true, scan: { status: 'succeeded' } });
  }, 30_000);

  it('fetches an issuer’s keys for the token checker', async () => {
    const { scan } = await read(await handler.fetch(post({ target: lab.origin, kind: 'issuer-keys' })));
    expect(scan).toMatchObject({ kind: 'issuer-keys', status: 'succeeded' });
    expect((scan!.report as { found: boolean; jwks?: { keys: unknown[] } }).jwks?.keys).toHaveLength(1);
  }, 30_000);
});

describe('what the function refuses before any connection is made', () => {
  it.each([
    ['https://127.0.0.1/', 'address-not-allowed'],
    ['https://169.254.169.254/latest/meta-data/', 'address-not-allowed'],
    ['http://example.com/', 'scheme-not-allowed'],
    ['https://example.com:22/', 'port-not-allowed'],
    ['not a url', 'invalid-url'],
  ])('%s -> %s', async (target, code) => {
    const response = await handler.fetch(post({ target }));
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ error: { code } });
  });

  it('a request from another site', async () => {
    const response = await handler.fetch(post({ target: 'https://example.com/' }, { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' }));
    expect(response.status).toBe(403);
  });

  it('anything but a JSON POST', async () => {
    expect((await handler.fetch(new Request(`https://${HOST}/api/v1/scan`, { method: 'GET' }))).status).toBe(405);
    expect((await handler.fetch(post('{not json'))).status).toBe(400);
    expect((await handler.fetch(post({ nope: 1 }))).status).toBe(400);
  });

  it('too many scans from one visitor, and too many of one service, whoever asks', async () => {
    const now = Date.now();
    memory.byClient.set('203.0.113.7', Array.from({ length: LIMITS.scansPerWindow }, () => now));
    const limited = await handler.fetch(post({ target: 'https://example.com/' }));
    expect(limited.status).toBe(429);
    expect(limited.headers.get('retry-after')).toBe('60');
    expect(await limited.json()).toMatchObject({ error: { code: 'rate-limited' } });

    memory.reset();
    memory.byService.set('example.com:443', Array.from({ length: LIMITS.perHostPerMinute }, () => now));
    const busy = await handler.fetch(post({ target: 'https://example.com/' }, {}, '198.51.100.9'));
    expect(await busy.json()).toMatchObject({ error: { code: 'host-busy' } });
  });

  it('an instance that is full', async () => {
    memory.active = LIMITS.maxActive;
    const response = await handler.fetch(post({ target: 'https://example.com/' }));
    expect(response.status).toBe(503);
  });
});
