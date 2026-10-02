import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { connectPinned, ConnectError } from './connect.ts';
import { DEFAULT_POLICY, parseTarget, TargetRejected } from './policy.ts';
import type { RejectionCode } from './policy.ts';
import { resolveTarget } from './resolve.ts';
import type { Lookup, PinnedTarget, ResolvedAddress } from './resolve.ts';

const answers =
  (...list: string[]): Lookup =>
  () =>
    Promise.resolve(list.map((address): ResolvedAddress => ({ address, family: address.includes(':') ? 6 : 4 })));

async function rejection(input: string, lookup: Lookup): Promise<RejectionCode | 'accepted'> {
  try {
    await resolveTarget(parseTarget(input), { lookup });
    return 'accepted';
  } catch (error) {
    if (error instanceof TargetRejected) return error.code;
    throw error;
  }
}

describe('resolving a host name', () => {
  it('pins a public address and reports everything the name resolved to', async () => {
    const pinned = await resolveTarget(parseTarget('https://login.example.com'), { lookup: answers('2606:4700::1111', '93.184.216.34') });
    expect(pinned).toMatchObject({ hostname: 'login.example.com', port: 443, address: '93.184.216.34', family: 4, hasHostname: true });
    expect(pinned.resolved.map((r) => r.address)).toEqual(['2606:4700::1111', '93.184.216.34']);
  });

  it.each([
    ['a public name pointing at loopback', ['127.0.0.1']],
    ['a public name pointing at the metadata service', ['169.254.169.254']],
    ['a public name pointing at a private network', ['10.0.0.8']],
    ['an IPv6 answer that wraps a private IPv4 address', ['::ffff:192.168.1.10']],
    ['an IPv6 loopback answer', ['::1']],
    ['a unique-local IPv6 answer', ['fd12:3456::1']],
    // The attacker hopes the scanner checks one answer and connects to another.
    ['one public and one internal answer', ['93.184.216.34', '10.0.0.8']],
    ['an internal answer hidden behind a public one in the other family', ['93.184.216.34', 'fe80::1']],
  ])('refuses %s', async (_what, list) => {
    expect(await rejection('https://innocent.example.com', answers(...list))).toBe('address-not-allowed');
  });

  it('reports a failed or empty lookup as a DNS failure', async () => {
    expect(await rejection('https://nope.example.com', () => Promise.reject(Object.assign(new Error('x'), { code: 'ENOTFOUND' })))).toBe('dns-failure');
    expect(await rejection('https://nope.example.com', answers())).toBe('dns-failure');
    expect(await rejection('https://nope.example.com', answers('not-an-address'))).toBe('dns-failure');
  });

  it('gives up on a resolver that never answers', async () => {
    const never: Lookup = () => new Promise(() => {});
    await expect(resolveTarget(parseTarget('https://slow.example.com'), { lookup: never, timeoutMs: 30 })).rejects.toMatchObject({ code: 'dns-failure' });
  });

  it('does not resolve an IP literal at all', async () => {
    let calls = 0;
    const lookup: Lookup = () => {
      calls++;
      return Promise.resolve([]);
    };
    const pinned = await resolveTarget(parseTarget('https://1.1.1.1'), { lookup });
    expect(pinned).toMatchObject({ address: '1.1.1.1', hasHostname: false });
    expect(calls).toBe(0);
  });
});

describe('DNS rebinding', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('connects to the address that was checked, however the name resolves afterwards', async () => {
    // A rebinding resolver: the first answer is harmless, every later answer is internal.
    let lookups = 0;
    const rebinding: Lookup = () => Promise.resolve([{ address: ++lookups === 1 ? '93.184.216.34' : '127.0.0.1', family: 4 }]);

    const pinned = await resolveTarget(parseTarget('https://rebind.example.com'), { lookup: rebinding });
    expect(pinned.address).toBe('93.184.216.34');

    // Record where sockets are opened to, without sending anything to a real host.
    const dialled: net.TcpNetConnectOpts[] = [];
    vi.spyOn(net, 'connect').mockImplementation(((options: net.TcpNetConnectOpts) => {
      dialled.push(options);
      const socket = new net.Socket();
      queueMicrotask(() => socket.emit('error', Object.assign(new Error('refused'), { code: 'ECONNREFUSED' })));
      return socket;
    }) as unknown as typeof net.connect);

    for (let i = 0; i < 3; i++) {
      await expect(connectPinned(pinned, 500)).rejects.toMatchObject({ code: 'ECONNREFUSED' });
    }
    expect(lookups).toBe(1);
    expect(dialled.map((d) => d.host)).toEqual(['93.184.216.34', '93.184.216.34', '93.184.216.34']);
    // Node only calls `lookup` for host names. If it ever were called, it must fail rather than resolve.
    expect(() => (dialled[0]!.lookup as () => void)()).toThrow(/Unexpected DNS lookup/);
  });

  it('opens a real connection to a pinned loopback address for a lab target', async () => {
    const server = net.createServer((socket) => socket.end('hello'));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      const policy = { ...DEFAULT_POLICY, labOrigins: [`https://localhost:${port}`] };
      const pinned = await resolveTarget(parseTarget(`https://localhost:${port}`, policy), { lookup: answers('127.0.0.1') });
      const socket = await connectPinned(pinned, 1000);
      const greeting = await new Promise<string>((resolve) => socket.once('data', (d: Buffer) => resolve(d.toString())));
      socket.destroy();
      expect(greeting).toBe('hello');
    } finally {
      server.close();
    }
  });

  it('refuses to connect to anything that is not a pinned IP address', async () => {
    const unpinned = { hostname: 'example.com', port: 443, address: 'example.com', family: 4, resolved: [], isLab: false, hasHostname: true } as PinnedTarget;
    await expect(connectPinned(unpinned, 100)).rejects.toBeInstanceOf(ConnectError);
  });
});

describe('lab origins', () => {
  it('lets a listed origin resolve to loopback, and nothing else', async () => {
    const policy = { ...DEFAULT_POLICY, labOrigins: ['https://localhost:9441'] };
    const pinned = await resolveTarget(parseTarget('https://localhost:9441', policy), { lookup: answers('127.0.0.1') });
    expect(pinned).toMatchObject({ address: '127.0.0.1', isLab: true });
    expect(() => parseTarget('https://localhost:9442', policy)).toThrow(TargetRejected);
  });
});
