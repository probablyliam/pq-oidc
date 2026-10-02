import { describe, expect, it } from 'vitest';
import { discoveryCandidates } from './discover.ts';

describe('where OpenID Connect metadata is looked for', () => {
  it('for an address the user typed, tries every path prefix as an issuer, deepest first', () => {
    expect(discoveryCandidates(new URL('https://idp.example/realms/payroll'), true)).toEqual([
      'https://idp.example/realms/payroll/.well-known/openid-configuration',
      'https://idp.example/realms/.well-known/openid-configuration',
      'https://idp.example/.well-known/openid-configuration',
      'https://idp.example/.well-known/oauth-authorization-server',
    ]);
  });

  it('for an endpoint a redirect landed on, drops the endpoint and tries the prefixes above it', () => {
    // The shape of a Microsoft sign-in: the metadata lives under /common, not at the root.
    expect(discoveryCandidates(new URL('https://login.example.com/common/oauth2/v2.0/authorize?client_id=x'), false)).toEqual([
      'https://login.example.com/common/oauth2/v2.0/.well-known/openid-configuration',
      'https://login.example.com/common/oauth2/.well-known/openid-configuration',
      'https://login.example.com/common/.well-known/openid-configuration',
      'https://login.example.com/.well-known/openid-configuration',
      'https://login.example.com/.well-known/oauth-authorization-server',
    ]);
  });

  it('goes straight to a metadata document when given one', () => {
    expect(discoveryCandidates(new URL('https://idp.example/x/.well-known/openid-configuration'), true)).toEqual(['https://idp.example/x/.well-known/openid-configuration']);
  });
});
