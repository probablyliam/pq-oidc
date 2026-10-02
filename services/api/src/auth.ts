/**
 * Sign-in. The API is an OpenID Connect relying party and the browser only
 * ever holds a session cookie (ADR 0009):
 *
 *   GET  /auth/login      start: PKCE, state and nonce are stored server-side, keyed by a short-lived cookie
 *   GET  /auth/callback   finish: openid-client checks state, PKCE and the token's claims; the ID token's
 *                         signature is then verified against an algorithm allowlist
 *   POST /auth/logout     end the session here, and hand back the provider's logout URL
 *
 * Nothing here implements the protocol: `openid-client` does. This module
 * decides what to store and what to send the browser.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { createRemoteJWKSet, customFetch as joseCustomFetch } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import * as oidc from 'openid-client';
import { rewritingFetch, TokenRejectedError, verifyIdToken } from '@pq-oidc/token-kit';
import type { ApiConfig } from './config.ts';
import { HttpError, readCookies, serializeCookie } from './http.ts';
import type { Logger } from './log.ts';
import type { Session, Store, User } from './store.ts';

const LOGIN_COOKIE = 'pq_login';
const SESSION_COOKIE = 'pq_session';
const LOGIN_TTL_MS = 10 * 60 * 1000;

export interface SessionContext {
  user: User;
  session: Session;
  /** Hash of the session ID: what the store knows the session by. */
  idHash: string;
}

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const randomId = () => randomBytes(32).toString('base64url');

/** Only same-site paths: "/x" yes, "//evil.example" and "/\evil.example" no. */
export function safeReturnTo(value: string | null): string {
  return value && /^\/(?![/\\])/.test(value) && !/[\r\n]/.test(value) ? value : '/';
}

function safeEqual(a: string, b: string): boolean {
  const [x, y] = [createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest()];
  return timingSafeEqual(x, y);
}

export class Auth {
  private readonly config: ApiConfig;
  private readonly store: Store;
  private readonly secure: boolean;
  private readonly redirectUri: string;
  private readonly now: () => number;
  private provider: Promise<{ config: oidc.Configuration; jwks: JWTVerifyGetKey }> | undefined;

  constructor(config: ApiConfig, store: Store, now: () => number = Date.now) {
    this.config = config;
    this.store = store;
    this.now = now;
    this.secure = config.publicUrl.startsWith('https:');
    this.redirectUri = `${config.publicUrl}/auth/callback`;
  }

  /** Discovers the provider on first use, and again later if that failed (the provider may start after the API). */
  private getProvider() {
    const { issuer, internalIssuer, clientId, clientSecret } = this.config.oidc;
    const backChannel = rewritingFetch(issuer, internalIssuer);
    this.provider ??= (async () => {
      const config = await oidc.discovery(new URL(issuer), clientId, { client_secret: clientSecret }, oidc.ClientSecretBasic(clientSecret), {
        [oidc.customFetch]: backChannel,
        // Plain http is for a provider on localhost during development only.
        execute: issuer.startsWith('http:') ? [oidc.allowInsecureRequests] : [],
      });
      const jwksUri = config.serverMetadata().jwks_uri;
      if (!jwksUri) throw new Error('The identity provider publishes no jwks_uri');
      return { config, jwks: createRemoteJWKSet(new URL(jwksUri), { [joseCustomFetch]: backChannel }) };
    })().catch((error: unknown) => {
      this.provider = undefined;
      throw error;
    });
    return this.provider;
  }

  /** Is the identity provider reachable? For the readiness of sign-in, not of the API as a whole. */
  async providerAvailable(): Promise<boolean> {
    return this.getProvider().then(
      () => true,
      () => false,
    );
  }

  private cookie(name: string, value: string, maxAgeSeconds: number, path = '/') {
    return serializeCookie(name, value, { secure: this.secure, maxAgeSeconds, path });
  }

  async startLogin(returnTo: string | null): Promise<{ location: string; setCookie: string }> {
    const { config } = await this.getProvider().catch(() => {
      throw new HttpError(503, 'identity-provider-unavailable', 'The sign-in service cannot be reached right now.');
    });
    const attempt = { state: oidc.randomState(), nonce: oidc.randomNonce(), codeVerifier: oidc.randomPKCECodeVerifier(), returnTo: safeReturnTo(returnTo) };
    const attemptId = randomId();
    this.store.saveLoginAttempt(sha256(attemptId), attempt, this.now() + LOGIN_TTL_MS);
    const location = oidc.buildAuthorizationUrl(config, {
      redirect_uri: this.redirectUri,
      scope: 'openid profile email',
      code_challenge: await oidc.calculatePKCECodeChallenge(attempt.codeVerifier),
      code_challenge_method: 'S256',
      state: attempt.state,
      nonce: attempt.nonce,
    });
    return { location: location.href, setCookie: this.cookie(LOGIN_COOKIE, attemptId, LOGIN_TTL_MS / 1000, '/auth') };
  }

  /**
   * Finishes a sign-in. Returns where to send the browser and the cookies to
   * set; on failure, a short code the web app can explain.
   */
  async finishLogin(req: IncomingMessage, url: URL, log: Logger): Promise<{ location: string; setCookie: string[] }> {
    const clearLogin = this.cookie(LOGIN_COOKIE, '', 0, '/auth');
    const fail = (code: string) => ({ location: `/?signin_error=${code}`, setCookie: [clearLogin] });

    const attemptId = readCookies(req).get(LOGIN_COOKIE);
    const attempt = attemptId ? this.store.takeLoginAttempt(sha256(attemptId), this.now()) : undefined;
    if (!attempt) return fail('expired');

    let idToken: string;
    let claims: Record<string, unknown>;
    try {
      const { config, jwks } = await this.getProvider();
      const tokens = await oidc.authorizationCodeGrant(config, new URL(url.pathname + url.search, this.config.publicUrl), {
        pkceCodeVerifier: attempt.codeVerifier,
        expectedState: attempt.state,
        expectedNonce: attempt.nonce,
        idTokenExpected: true,
      });
      if (!tokens.id_token) throw new TokenRejectedError('malformed', 'The provider did not return an ID token.');
      idToken = tokens.id_token;
      // openid-client trusts an ID token that arrives straight from the token endpoint over TLS
      // (OIDC Core §3.1.3.7 permits that). The signature is checked here anyway, against this
      // app's own allowlist, so an unexpected algorithm is refused rather than silently accepted.
      const verified = await verifyIdToken(idToken, jwks, {
        issuer: this.config.oidc.issuer,
        audience: this.config.oidc.clientId,
        algorithms: this.config.oidc.idTokenAlgs,
        nonce: attempt.nonce,
      });
      claims = verified.payload;
    } catch (error) {
      if (error instanceof oidc.AuthorizationResponseError) {
        log.info('sign-in was refused by the provider', { error: error.error });
        return fail(error.error === 'access_denied' ? 'cancelled' : 'refused');
      }
      if (error instanceof TokenRejectedError) {
        log.warn('ID token rejected', { reason: error.code });
        return fail('token-rejected');
      }
      log.warn('sign-in failed', { error });
      return fail('failed');
    }

    const now = this.now();
    const user = this.store.upsertUser(
      {
        id: randomUUID(),
        issuer: this.config.oidc.issuer,
        sub: String(claims.sub),
        name: typeof claims.name === 'string' ? claims.name.slice(0, 200) : null,
        email: typeof claims.email === 'string' ? claims.email.slice(0, 320) : null,
      },
      now,
    );
    const sessionId = randomId();
    this.store.createSession(sha256(sessionId), { userId: user.id, csrfToken: randomId(), idToken, expiresAt: now + this.config.sessionTtlMs }, now);
    log.info('signed in', { userId: user.id });
    return { location: attempt.returnTo, setCookie: [clearLogin, this.cookie(SESSION_COOKIE, sessionId, this.config.sessionTtlMs / 1000)] };
  }

  /** The signed-in user for this request, if there is one. */
  sessionFor(req: IncomingMessage): SessionContext | undefined {
    const sessionId = readCookies(req).get(SESSION_COOKIE);
    if (!sessionId) return undefined;
    const idHash = sha256(sessionId);
    const session = this.store.getSession(idHash, this.now());
    const user = session && this.store.getUser(session.userId);
    return session && user ? { session, user, idHash } : undefined;
  }

  /**
   * Refuses a state-changing request unless it comes from this site's own
   * pages: the per-session token must be in a header (which another site
   * cannot set without a preflight this server never approves), and when the
   * browser says where the request came from, it must be here.
   */
  requireSameSite(req: IncomingMessage, context: SessionContext) {
    const token = req.headers['x-csrf-token'];
    const origin = req.headers.origin;
    const site = req.headers['sec-fetch-site'];
    const tokenOk = typeof token === 'string' && safeEqual(token, context.session.csrfToken);
    const originOk = origin === undefined || origin === new URL(this.config.publicUrl).origin;
    const siteOk = site === undefined || site === 'same-origin';
    if (!tokenOk || !originOk || !siteOk) throw new HttpError(403, 'csrf', 'This request did not come from the application.');
  }

  /** Ends the session and returns the cookie that clears it, plus the provider's logout URL if it has one. */
  async logout(context: SessionContext): Promise<{ setCookie: string; endSessionUrl?: string }> {
    this.store.deleteSession(context.idHash);
    let endSessionUrl: string | undefined;
    try {
      const { config } = await this.getProvider();
      if (config.serverMetadata().end_session_endpoint && context.session.idToken) {
        endSessionUrl = oidc.buildEndSessionUrl(config, { id_token_hint: context.session.idToken, post_logout_redirect_uri: `${this.config.publicUrl}/` }).href;
      }
    } catch {
      // The local session is gone either way; the provider's session ends when it expires.
    }
    return { setCookie: this.cookie(SESSION_COOKIE, '', 0), endSessionUrl };
  }
}
