import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TestBrowser } from './support/browser.ts';
import { startStack } from './support/stack.ts';
import type { Stack } from './support/stack.ts';

/**
 * Full sign-ins through real HTTP: browser → app → provider → login form →
 * back to the app, which verifies the ID token and shows the result.
 */
describe('end to end: both apps during the migration', () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await startStack();
  });
  afterAll(() => stack.close());

  it('signs in to Legacy App with an ES256 ID token that fits in a cookie', async () => {
    const browser = new TestBrowser();
    const loginPage = await browser.navigate(`${stack.legacyUrl}/login`);
    expect(loginPage.body).toContain('Legacy App');
    expect(loginPage.body).toContain('ES256');

    const home = await browser.submitLogin(loginPage, 'alice', 'quantum-safe');
    expect(home.url).toBe(`${stack.legacyUrl}/`);
    expect(home.body).toContain('Hi, Alice');
    expect(home.body).toContain('<b>ES256</b>');
    expect(home.body).toContain('Your browser kept the');
    expect(browser.droppedCookies).toEqual([]);
  });

  it('signs in to PQ-Ready App with an ML-DSA-65 ID token, and the browser drops the oversized cookie', async () => {
    const browser = new TestBrowser();
    const loginPage = await browser.navigate(`${stack.pqUrl}/login`);
    const home = await browser.submitLogin(loginPage, 'bob', 'quantum-safe');

    expect(home.body).toContain('Hi, Bob');
    expect(home.body).toContain('<b>ML-DSA-65</b>');
    expect(home.body).toContain('3,309 B'); // FIPS 204 signature size
    expect(home.body).toContain('silently dropped');
    expect(browser.droppedCookies).toEqual(['pq-app.id_token']);
    // The session cookie is tiny, so the user stays signed in regardless.
    expect(browser.cookie('127.0.0.1', 'pq-app.sid')).toBeDefined();
  });

  it('uses single sign-on: the second app does not ask for the password again', async () => {
    const browser = new TestBrowser();
    await browser.submitLogin(await browser.navigate(`${stack.pqUrl}/login`), 'alice', 'quantum-safe');
    const secondApp = await browser.navigate(`${stack.legacyUrl}/login`);
    expect(secondApp.url).toBe(`${stack.legacyUrl}/`);
    expect(secondApp.body).toContain('Hi, Alice');
  });

  it('keeps users on the login page after a wrong password', async () => {
    const browser = new TestBrowser();
    const page = await browser.submitLogin(await browser.navigate(`${stack.legacyUrl}/login`), 'alice', 'wrong');
    expect(page.status).toBe(401);
    expect(page.body).toContain('Wrong username or password.');
  });

  it('reports a cancelled sign-in back to the app as access_denied', async () => {
    const browser = new TestBrowser();
    const loginPage = await browser.navigate(`${stack.legacyUrl}/login`);
    const cancelHref = /href="(\/interaction\/[^"]+\/abort)"/.exec(loginPage.body)?.[1];
    const page = await browser.navigate(new URL(cancelHref ?? '', loginPage.url).href);
    expect(page.body).toContain('Sign-in rejected');
    expect(page.body).toContain('access_denied');
  });

  it('signs out', async () => {
    const browser = new TestBrowser();
    await browser.submitLogin(await browser.navigate(`${stack.legacyUrl}/login`), 'alice', 'quantum-safe');
    const page = await browser.navigate(`${stack.legacyUrl}/logout`, { method: 'POST' });
    expect(page.body).toContain('Sign in with pq-oidc');
  });
});

describe('end to end: switching an app before it is ready', () => {
  let stack: Stack;
  beforeAll(async () => {
    // The mistake a careful migration avoids: moving Legacy App to ML-DSA-65
    // before its library supports it.
    stack = await startStack({ legacyAlg: 'ML-DSA-65' });
  });
  afterAll(() => stack.close());

  it('Legacy App refuses the post-quantum token and explains why', async () => {
    const browser = new TestBrowser();
    const page = await browser.submitLogin(await browser.navigate(`${stack.legacyUrl}/login`), 'alice', 'quantum-safe');
    expect(page.status).toBe(401);
    expect(page.body).toContain('Sign-in rejected');
    expect(page.body).toContain('signed with ML-DSA-65, but this app only accepts ES256');
    expect(page.body).toContain('alg-not-allowed');
  });

  it('PQ-Ready App is unaffected', async () => {
    const browser = new TestBrowser();
    const page = await browser.submitLogin(await browser.navigate(`${stack.pqUrl}/login`), 'alice', 'quantum-safe');
    expect(page.body).toContain('Hi, Alice');
  });
});

describe('end to end: PQ-Ready App still accepts ES256', () => {
  let stack: Stack;
  beforeAll(async () => {
    // Rolling back PQ-Ready App to the classical key must not break it.
    stack = await startStack({ pqAlg: 'ES256' });
  });
  afterAll(() => stack.close());

  it('signs in with an ES256 token (rollback path)', async () => {
    const browser = new TestBrowser();
    const page = await browser.submitLogin(await browser.navigate(`${stack.pqUrl}/login`), 'alice', 'quantum-safe');
    expect(page.body).toContain('<b>ES256</b>');
  });
});
