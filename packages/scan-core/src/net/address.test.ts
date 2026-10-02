import { describe, expect, it } from 'vitest';
import { classifyAddress, parseIpv4, parseIpv6 } from './address.ts';

describe('IPv4 addresses', () => {
  it.each([
    ['0.0.0.0', 'this network'],
    ['0.1.2.3', 'this network'],
    ['10.0.0.1', 'private'],
    ['10.255.255.255', 'private'],
    ['100.64.0.1', 'carrier-grade NAT'],
    ['100.127.255.254', 'carrier-grade NAT'],
    ['127.0.0.1', 'loopback'],
    ['127.255.255.254', 'loopback'],
    ['169.254.169.254', 'link-local'], // AWS, GCP and Azure metadata
    ['169.254.170.2', 'link-local'], // ECS task metadata
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.0.0.1', 'IETF protocol assignments'],
    ['192.0.2.10', 'documentation'],
    ['192.88.99.1', '6to4'],
    ['192.168.1.1', 'private'],
    ['198.18.0.1', 'benchmarking'],
    ['198.19.255.255', 'benchmarking'],
    ['198.51.100.7', 'documentation'],
    ['203.0.113.7', 'documentation'],
    ['224.0.0.1', 'multicast'],
    ['239.255.255.255', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['255.255.255.255', 'reserved'],
  ])('refuses %s (%s)', (address, why) => {
    const verdict = classifyAddress(address);
    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toContain(why);
  });

  it.each(['1.1.1.1', '8.8.8.8', '100.63.255.255', '100.128.0.1', '172.15.255.255', '172.32.0.1', '192.167.255.255', '198.17.255.255', '198.20.0.1', '223.255.255.255'])(
    'allows the public address %s',
    (address) => {
      expect(classifyAddress(address)).toEqual({ address, family: 4, allowed: true, reason: undefined });
    },
  );

  it.each(['127.1', '0177.0.0.1', '0x7f.0.0.1', '2130706433', '127.0.0.01', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.-4', ' 1.2.3.4', '1.2.3.4 '])(
    'does not accept the non-canonical form %s as an address',
    (text) => {
      expect(parseIpv4(text)).toBeUndefined();
      expect(classifyAddress(text).allowed).toBe(false);
    },
  );
});

describe('IPv6 addresses', () => {
  it.each([
    ['::', 'unspecified'],
    ['::1', 'loopback'],
    ['0:0:0:0:0:0:0:1', 'loopback'],
    ['::7f00:1', 'IPv4-compatible'],
    ['::127.0.0.1', 'IPv4-compatible'],
    ['64:ff9b:1::1', 'local-use NAT64'],
    ['100::1', 'discard-only'],
    ['2001::1', 'Teredo'],
    ['2001:0:4136:e378:8000:63bf:3fff:fdd2', 'Teredo'],
    ['2001:db8::1', 'documentation'],
    ['3fff::1', 'documentation'],
    ['fc00::1', 'unique local'],
    ['fd00:ec2::254', 'unique local'], // AWS metadata over IPv6
    ['fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'unique local'],
    ['fe80::1', 'link-local'],
    ['febf::1', 'link-local'],
    ['fec0::1', 'site-local'],
    ['ff02::1', 'multicast'],
    ['4000::1', 'outside global unicast'],
    ['e000::1', 'outside global unicast'],
  ])('refuses %s (%s)', (address, why) => {
    const verdict = classifyAddress(address);
    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toContain(why);
  });

  it.each(['2606:4700:4700::1111', '2001:4860:4860::8888', '2a00:1450:4001:81b::200e', '2001:200::1', '[2606:4700::1111]'])(
    'allows the public address %s',
    (address) => {
      expect(classifyAddress(address).allowed).toBe(true);
    },
  );

  it.each([
    ['::ffff:127.0.0.1', '127.0.0.1', 'loopback'],
    ['::ffff:7f00:1', '127.0.0.1', 'loopback'],
    ['0:0:0:0:0:ffff:7f00:0001', '127.0.0.1', 'loopback'],
    ['::ffff:169.254.169.254', '169.254.169.254', 'link-local'],
    ['::ffff:a9fe:a9fe', '169.254.169.254', 'link-local'],
    ['::ffff:10.0.0.1', '10.0.0.1', 'private'],
    ['64:ff9b::7f00:1', '127.0.0.1', 'loopback'],
    ['64:ff9b::10.1.2.3', '10.1.2.3', 'private'],
    ['2002:7f00:1::', '127.0.0.1', 'loopback'],
    ['2002:c0a8:101::1', '192.168.1.1', 'private'],
    ['2002:a9fe:a9fe::', '169.254.169.254', 'link-local'],
  ])('judges %s by the IPv4 address inside it (%s)', (address, embedded, why) => {
    const verdict = classifyAddress(address);
    expect(verdict.embeddedIpv4).toBe(embedded);
    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toContain(why);
  });

  it('allows a mapped or NAT64 form of a public IPv4 address', () => {
    expect(classifyAddress('::ffff:8.8.8.8')).toMatchObject({ allowed: true, embeddedIpv4: '8.8.8.8' });
    expect(classifyAddress('64:ff9b::808:808')).toMatchObject({ allowed: true, embeddedIpv4: '8.8.8.8' });
  });

  it.each(['fe80::1%eth0', '::1%lo', '1::2::3', ':::', ':', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '12345::', 'g::1', '1.2.3.4::1', '::1.2.3', '::1.2.3.4:5', ''])(
    'refuses the malformed address %j',
    (text) => {
      expect(parseIpv6(text)).toBeUndefined();
      expect(classifyAddress(text).allowed).toBe(false);
    },
  );

  it('reads `::` compression and a dotted tail', () => {
    expect([...parseIpv6('1::2')!]).toEqual([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    expect([...parseIpv6('::ffff:1.2.3.4')!].slice(10)).toEqual([0xff, 0xff, 1, 2, 3, 4]);
    expect([...parseIpv6('1:2:3:4:5:6:1.2.3.4')!].slice(12)).toEqual([1, 2, 3, 4]);
  });
});
