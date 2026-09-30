import { createHash, randomBytes } from 'node:crypto';
import { createLocalJWKSet } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { measureJwt, verifyIdToken } from '@pq-oidc/token-kit';
import { TestBrowser } from './support/browser.ts';
import { startStack } from './support/stack.ts';
import type { Stack } from './support/stack.ts';

/**
 * Protocol-level tests that talk to the provider directly, the way an attacker
 * or a misbehaving client would. Each test maps to a row in docs/threat-model.md.
 */
let stack: Stack;
beforeAll(async () => {
  stack = await startStack();
});
afterAll(() => stack.close());

const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
};

function client(id: 'legacy-app' | 'pq-app') {
  const c = stack.clients.find((x) => x.clientId === id);
  if (!c) throw new Error(`no client ${id}`);
  return c;
}

const isCallback = (url: URL) => url.pathname === '/callback';

/** Runs the authorization request as a browser and returns the URL the provider sends the user back to. */
async function authorize(params: Record<string, string>, browser = new TestBrowser()) {
  const url = `${stack.issuer}/auth?${new URLSearchParams(params)}`;
  let page = await browser.navigate(url, { stopWhen: isCallback });
  if (!isCallback(new URL(page.url)) && page.body.includes('action="/interaction/')) {
    page = await browser.submitLogin(page, 'alice', 'quantum-safe', { stopWhen: isCallback });
  }
  return page;
}

function authParams(clientId: 'legacy-app' | 'pq-app', challenge: string, extra: Record<string, string> = {}) {
  return {
    client_id: clientId,
    response_type: 'code',
    scope: 'openid profile email',
    redirect_uri: client(clientId).redirectUri,
    state: 'state-123',
    nonce: 'nonce-123',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  };
}

async function redeem(clientId: 'legacy-app' | 'pq-app', code: string, verifier: string, secret?: string) {
  const c = client(clientId);
  const basic = Buffer.from(`${c.clientId}:${secret ?? c.clientSecret}`).toString('base64');
  const response = await fetch(`${stack.issuer}/token`, {
    method: 'POST',
    headers: { authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: c.redirectUri, code_verifier: verifier }),
  });
  return { status: response.status, body: (await response.json()) as Record<string, string> };
}

async function getCode(clientId: 'legacy-app' | 'pq-app') {
  const { verifier, challenge } = pkce();
  const page = await authorize(authParams(clientId, challenge));
  const code = new URL(page.url).searchParams.get('code');
  if (!code) throw new Error(`expected a code, got ${page.url}`);
  return { code, verifier };
}

describe('discovery and keys', () => {
  it('advertises only the OAuth 2.1 subset: code flow with S256 PKCE', async () => {
    const meta = (await (await fetch(`${stack.issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.response_types_supported).toEqual(['code']);
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
    expect(meta.id_token_signing_alg_values_supported).toEqual(['ES256', 'ML-DSA-65']);
  });

  it('publishes one classical and one post-quantum key, with no private material', async () => {
    const jwks = (await (await fetch(`${stack.issuer}/jwks`)).json()) as JSONWebKeySet;
    expect(jwks.keys.map((k) => [k.kty, k.alg])).toEqual([
      ['EC', 'ES256'],
      ['AKP', 'ML-DSA-65'],
    ]);
    for (const key of jwks.keys) {
      expect(key).not.toHaveProperty('d'); // EC private scalar
      expect(key).not.toHaveProperty('priv'); // ML-DSA seed (RFC 9964)
    }
  });
});

describe('ID tokens are signed with the algorithm registered for each app', () => {
  it.each([
    ['legacy-app', 'ES256', 64],
    ['pq-app', 'ML-DSA-65', 3309],
  ] as const)('%s receives %s', async (clientId, alg, signatureBytes) => {
    const { code, verifier } = await getCode(clientId);
    const { status, body } = await redeem(clientId, code, verifier);
    expect(status).toBe(200);

    const jwks = (await (await fetch(`${stack.issuer}/jwks`)).json()) as JSONWebKeySet;
    const { header, payload } = await verifyIdToken(body.id_token ?? '', createLocalJWKSet(jwks), {
      issuer: stack.issuer,
      audience: clientId,
      algorithms: [alg],
      nonce: 'nonce-123',
    });
    expect(header.alg).toBe(alg);
    expect(payload.email).toBe('alice.nakamura@example.com');
    expect(measureJwt(body.id_token ?? '').signatureBytes).toBe(signatureBytes);
  });
});

describe('authorization request attacks', () => {
  it('rejects requests without PKCE', async () => {
    const { challenge } = pkce();
    const withoutPkce: Record<string, string> = authParams('legacy-app', challenge);
    delete withoutPkce.code_challenge;
    delete withoutPkce.code_challenge_method;
    const page = await authorize(withoutPkce);
    expect(new URL(page.url).searchParams.get('error')).toBe('invalid_request');
  });

  it('rejects the weak "plain" PKCE method', async () => {
    const page = await authorize(authParams('legacy-app', 'x'.repeat(43), { code_challenge_method: 'plain' }));
    expect(new URL(page.url).searchParams.get('error')).toBe('invalid_request');
  });

  it('rejects the implicit flow (response_type=token), which OAuth 2.1 removes', async () => {
    const { challenge } = pkce();
    const page = await authorize(authParams('legacy-app', challenge, { response_type: 'token' }));
    // Token-style responses use the URL fragment (response_mode=fragment), so the error arrives there.
    const fragment = new URLSearchParams(new URL(page.url).hash.slice(1));
    expect(fragment.get('error')).toBe('unsupported_response_type');
    expect(fragment.has('access_token')).toBe(false);
  });

  it('never redirects to an unregistered redirect_uri (stops open redirects and code theft)', async () => {
    const { challenge } = pkce();
    const page = await authorize(
      authParams('legacy-app', challenge, { redirect_uri: 'https://attacker.example/callback' }),
    );
    expect(page.status).toBe(400);
    expect(page.url).toContain(stack.issuer);
    expect(page.body).toContain('invalid_redirect_uri');
  });

  it('rejects unknown clients', async () => {
    const { challenge } = pkce();
    const page = await authorize({ ...authParams('legacy-app', challenge), client_id: 'evil-app' });
    expect(page.status).toBe(400);
    expect(page.body).toContain('invalid_client');
  });
});

describe('token endpoint attacks', () => {
  it('lets an authorization code be used only once', async () => {
    const { code, verifier } = await getCode('legacy-app');
    expect((await redeem('legacy-app', code, verifier)).status).toBe(200);
    const replay = await redeem('legacy-app', code, verifier);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');
  });

  it('rejects a stolen code without the matching PKCE verifier', async () => {
    const { code } = await getCode('legacy-app');
    const attempt = await redeem('legacy-app', code, pkce().verifier);
    expect(attempt.body.error).toBe('invalid_grant');
  });

  it('rejects a wrong client secret', async () => {
    const { code, verifier } = await getCode('legacy-app');
    const attempt = await redeem('legacy-app', code, verifier, 'not-the-secret');
    expect(attempt.status).toBe(401);
    expect(attempt.body.error).toBe('invalid_client');
  });

  it("does not let one app redeem another app's code", async () => {
    const { code, verifier } = await getCode('pq-app');
    const attempt = await redeem('legacy-app', code, verifier);
    expect(attempt.body.error).toBe('invalid_grant');
  });
});

describe('login page hardening', () => {
  it('forbids framing and inline scripts', async () => {
    const { challenge } = pkce();
    const page = await new TestBrowser().navigate(
      `${stack.issuer}/auth?${new URLSearchParams(authParams('legacy-app', challenge))}`,
    );
    expect(page.body).toContain('Sign in');
    const csp = page.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toContain('unsafe-inline');
  });

  it('escapes user input echoed back into the page', async () => {
    const { challenge } = pkce();
    const browser = new TestBrowser();
    const loginPage = await browser.navigate(`${stack.issuer}/auth?${new URLSearchParams(authParams('legacy-app', challenge))}`);
    const page = await browser.submitLogin(loginPage, '<script>alert(1)</script>', 'wrong');
    expect(page.body).not.toContain('<script>alert(1)</script>');
    expect(page.body).toContain('&lt;script&gt;');
  });

  it('cannot finish a login from a different browser session (interaction CSRF)', async () => {
    const { challenge } = pkce();
    const victim = new TestBrowser();
    const loginPage = await victim.navigate(`${stack.issuer}/auth?${new URLSearchParams(authParams('legacy-app', challenge))}`);
    const attacker = new TestBrowser(); // has no _interaction cookie for this uid
    const page = await attacker.submitLogin(loginPage, 'alice', 'quantum-safe');
    expect(page.status).toBeGreaterThanOrEqual(400);
    expect(page.url).not.toContain('/callback');
  });
});
