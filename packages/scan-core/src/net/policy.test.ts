import { describe, expect, it } from 'vitest';
import { DEFAULT_POLICY, parseLabOrigins, parseTarget, TargetRejected } from './policy.ts';
import type { RejectionCode, TargetPolicy } from './policy.ts';

function rejection(input: string, policy?: TargetPolicy): RejectionCode | 'accepted' {
  try {
    parseTarget(input, policy);
    return 'accepted';
  } catch (error) {
    if (error instanceof TargetRejected) return error.code;
    throw error;
  }
}

describe('accepted targets', () => {
  it('normalises a public https address', () => {
    const target = parseTarget('  https://Accounts.Example.com/login?x=1#frag ');
    expect(target.url.href).toBe('https://accounts.example.com/login?x=1');
    expect(target).toMatchObject({ hostname: 'accounts.example.com', port: 443, hostFamily: 0, isLab: false });
  });

  it('assumes https when the scheme is left out', () => {
    expect(parseTarget('example.com/login').url.href).toBe('https://example.com/login');
    expect(parseTarget('example.com:8443').port).toBe(8443);
  });

  it('accepts a public IP literal and a trailing dot', () => {
    expect(parseTarget('https://1.1.1.1/')).toMatchObject({ hostname: '1.1.1.1', hostFamily: 4 });
    expect(parseTarget('https://[2606:4700:4700::1111]/')).toMatchObject({ hostname: '2606:4700:4700::1111', hostFamily: 6 });
    expect(parseTarget('https://example.com./').hostname).toBe('example.com');
  });
});

describe('scheme, port and credentials', () => {
  it.each(['http://example.com', 'ftp://example.com', 'file:///etc/passwd', 'gopher://example.com:70/_x', 'javascript://example.com/%0aalert(1)', 'data://text/plain,hi'])(
    'refuses %s',
    (input) => {
      expect(rejection(input)).toBe('scheme-not-allowed');
    },
  );

  it.each(['https://example.com:22', 'https://example.com:80', 'https://example.com:6379', 'https://example.com:10250', 'example.com:2379'])(
    'refuses the port in %s',
    (input) => {
      expect(rejection(input)).toBe('port-not-allowed');
    },
  );

  it('refuses credentials, which also hide the real host from a quick read', () => {
    expect(rejection('https://user:pass@example.com/')).toBe('credentials-in-url');
    expect(rejection('https://example.com@127.0.0.1/')).toBe('credentials-in-url');
    expect(rejection('https://example.com:443@169.254.169.254/')).toBe('credentials-in-url');
  });

  // The last one ends in a number, so the URL parser reads it as a malformed IPv4 address rather than a name.
  it.each(['', '   ', 'https://', 'https://[::1', 'https://exa mple.com', `https://example.com/${'a'.repeat(2100)}`, 'https://foo.123/', 'https://1.2.3.256/'])(
    'refuses the unusable input %j',
    (input) => {
      expect(rejection(input)).toBe('invalid-url');
    },
  );
});

describe('internal addresses written as IP literals', () => {
  it.each([
    'https://127.0.0.1/',
    'https://127.1/', // short form
    'https://2130706433/', // decimal
    'https://0x7f000001/', // hexadecimal
    'https://0x7f.0.0.1/',
    'https://0177.0.0.1/', // octal
    'https://017700000001/',
    'https://127.0.0.1./',
    'https://0/',
    'https://0.0.0.0/',
    'https://10.0.0.5/',
    'https://192.168.0.1:8443/',
    'https://172.16.5.4/',
    'https://169.254.169.254/latest/meta-data/',
    'https://2852039166/', // 169.254.169.254 in decimal
    'https://0xa9fea9fe/',
    'https://100.100.100.200/', // Alibaba Cloud metadata (CGNAT range)
    'https://[::1]/',
    'https://[0:0:0:0:0:0:0:1]/',
    'https://[::]/',
    'https://[::ffff:127.0.0.1]/',
    'https://[::ffff:7f00:1]/',
    'https://[::ffff:169.254.169.254]/',
    'https://[64:ff9b::7f00:1]/',
    'https://[2002:7f00:1::]/',
    'https://[fd00:ec2::254]/',
    'https://[fe80::1]/',
    'https://[fc00::1]/',
    'https://１２７.０.０.１/', // full-width digits, folded to ASCII by the URL parser
    'https://①②⑦.⓪.⓪.①/',
  ])('refuses %s', (input) => {
    expect(rejection(input)).toBe('address-not-allowed');
  });
});

describe('internal host names', () => {
  it.each([
    'https://localhost/',
    'https://LOCALHOST/',
    'https://localhost./',
    'https://app.localhost/',
    'https://printer.local/',
    'https://metadata.google.internal/',
    'https://kubernetes.default.svc/',
    'https://kubernetes.default.svc.cluster.local/',
    'https://router.lan/',
    'https://wiki.corp/',
    'https://nas.home.arpa/',
    'https://intranet/',
    'https://kubernetes/',
    'https://metadata/',
    'https:///path', // parsed as the host "path"
  ])('refuses %s', (input) => {
    expect(rejection(input)).toBe('hostname-not-allowed');
  });
});

describe('lab origins', () => {
  const policy: TargetPolicy = { ...DEFAULT_POLICY, labOrigins: parseLabOrigins('https://localhost:9441, http://127.0.0.1:3000') };

  it('exempts exactly the listed origin', () => {
    expect(parseTarget('https://localhost:9441/login', policy)).toMatchObject({ isLab: true, port: 9441 });
    expect(parseTarget('http://127.0.0.1:3000/.well-known/openid-configuration', policy)).toMatchObject({ isLab: true, port: 3000, hostFamily: 4 });
  });

  it('does not exempt a different port, scheme or host', () => {
    expect(rejection('https://localhost:9442/', policy)).toBe('port-not-allowed');
    expect(rejection('http://localhost:9441/', policy)).toBe('scheme-not-allowed');
    expect(rejection('https://127.0.0.1:9441/', policy)).toBe('port-not-allowed');
    expect(rejection('https://127.0.0.1:8443/', policy)).toBe('address-not-allowed');
    expect(rejection('http://127.0.0.1:3001/', policy)).toBe('scheme-not-allowed');
  });

  it('still refuses credentials for a lab origin', () => {
    expect(rejection('https://a:b@localhost:9441/', policy)).toBe('credentials-in-url');
  });

  it('is empty by default and refuses anything but a bare origin', () => {
    expect(DEFAULT_POLICY.labOrigins).toEqual([]);
    expect(parseLabOrigins(undefined)).toEqual([]);
    expect(() => parseLabOrigins('https://localhost:9441/path')).toThrow(/scheme:\/\/host:port/);
  });
});
