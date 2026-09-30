import { randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import * as oidc from 'openid-client';
import { createRemoteJWKSet, customFetch as joseCustomFetch } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import { measureJwt, securityHeaders, TokenRejectedError, verifyIdToken } from '@pq-oidc/token-kit';
import type { JwtMeasurement } from '@pq-oidc/token-kit';
import { clearCookie, readCookies, serializeCookie } from './cookies.ts';
import type { RpPreset } from './presets.ts';
import { rejectedPage, signedInPage, signedOutPage } from './views.ts';

export interface RpAppOptions {
  preset: RpPreset;
  clientSecret: string;
  /** This app's public URL, e.g. http://localhost:3002. */
  baseUrl: string;
  /** The provider's public URL (what browsers see, and the `iss` in tokens). */
  issuer: string;
  /**
   * Where this server can reach the provider, if different from `issuer`.
   * Inside Docker or Kubernetes, "localhost:3000" means the container itself,
   * so back-channel calls go to e.g. http://provider:3000 instead.
   */
  internalIssuer?: string;
  /** Link shown after sign-in so visitors can compare both apps. */
  otherAppUrl?: string;
}

interface PendingLogin {
  codeVerifier: string;
  state: string;
  nonce: string;
  expiresAt: number;
}

interface Session {
  token: string;
  claims: Record<string, unknown>;
  measurement: JwtMeasurement;
  expiresAt: number;
}

const LOGIN_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_MS = 60 * 60 * 1000;

export function createRpApp(options: RpAppOptions) {
  const { preset: app, baseUrl } = options;
  const secure = baseUrl.startsWith('https:');
  const redirectUri = `${baseUrl}/callback`;
  const cookie = {
    login: `${app.clientId}.login`,
    session: `${app.clientId}.sid`,
    // The naive approach we are testing: the entire ID token in a cookie.
    naiveToken: `${app.clientId}.id_token`,
  };

  // Server-side state. In memory is enough for a single-replica demo; a real
  // app would use Redis or a database so sessions survive restarts.
  const pendingLogins = new Map<string, PendingLogin>();
  const sessions = new Map<string, Session>();

  const backChannelFetch = rewritingFetch(options.issuer, options.internalIssuer);
  let configPromise: Promise<{ config: oidc.Configuration; jwks: JWTVerifyGetKey }> | undefined;

  /** Discovers the provider on first use (and retries later if the provider wasn't up yet). */
  function getProvider() {
    configPromise ??= (async () => {
      const config = await oidc.discovery(
        new URL(options.issuer),
        app.clientId,
        { client_secret: options.clientSecret },
        oidc.ClientSecretBasic(options.clientSecret),
        {
          [oidc.customFetch]: backChannelFetch,
          execute: options.issuer.startsWith('http:') ? [oidc.allowInsecureRequests] : [],
        },
      );
      const jwksUri = config.serverMetadata().jwks_uri;
      if (!jwksUri) throw new Error('Provider does not publish a jwks_uri');
      const jwks = createRemoteJWKSet(new URL(jwksUri), { [joseCustomFetch]: backChannelFetch });
      return { config, jwks };
    })().catch((error: unknown) => {
      configPromise = undefined;
      throw error;
    });
    return configPromise;
  }

  async function startLogin(res: ServerResponse) {
    const { config } = await getProvider();
    const login: PendingLogin = {
      codeVerifier: oidc.randomPKCECodeVerifier(),
      state: oidc.randomState(),
      nonce: oidc.randomNonce(),
      expiresAt: Date.now() + LOGIN_TTL_MS,
    };
    const loginId = randomId();
    pendingLogins.set(loginId, login);

    const authorizationUrl = oidc.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope: 'openid profile email',
      code_challenge: await oidc.calculatePKCECodeChallenge(login.codeVerifier),
      code_challenge_method: 'S256',
      state: login.state,
      nonce: login.nonce,
    });
    res.setHeader('Set-Cookie', serializeCookie(cookie.login, loginId, { maxAgeSeconds: LOGIN_TTL_MS / 1000, secure }));
    redirect(res, authorizationUrl.href);
  }

  async function finishLogin(req: IncomingMessage, res: ServerResponse, url: URL) {
    const loginId = readCookies(req).get(cookie.login) ?? '';
    const login = pendingLogins.get(loginId);
    pendingLogins.delete(loginId); // one attempt per login, success or not
    if (!login || login.expiresAt < Date.now()) {
      return sendPage(res, 400, (nonce) =>
        rejectedPage(nonce, app, 'login-expired', 'This sign-in attempt expired or was already used. Please try again.'),
      );
    }

    const { config, jwks } = await getProvider();
    try {
      // openid-client runs the protocol checks: state, PKCE, code exchange, iss/aud/nonce.
      const tokens = await oidc.authorizationCodeGrant(config, new URL(url.pathname + url.search, baseUrl), {
        pkceCodeVerifier: login.codeVerifier,
        expectedState: login.state,
        expectedNonce: login.nonce,
        idTokenExpected: true,
      });
      const idToken = tokens.id_token;
      if (!idToken) throw new TokenRejectedError('malformed', 'The provider did not return an ID token.');

      // openid-client does not check the ID token's signature when the token
      // arrives straight from the token endpoint over TLS (OIDC Core §3.1.3.7).
      // We check it anyway, with this app's own algorithm allowlist. That check
      // is what the post-quantum migration is about.
      const { payload } = await verifyIdToken(idToken, jwks, {
        issuer: options.issuer,
        audience: app.clientId,
        algorithms: app.acceptedAlgs,
        nonce: login.nonce,
      });

      const sid = randomId();
      const measurement = measureJwt(idToken, cookie.naiveToken);
      sessions.set(sid, { token: idToken, claims: payload, measurement, expiresAt: Date.now() + SESSION_TTL_MS });
      res.setHeader('Set-Cookie', [
        clearCookie(cookie.login, secure),
        serializeCookie(cookie.session, sid, { secure }),
        serializeCookie(cookie.naiveToken, idToken, { secure }),
      ]);
      redirect(res, '/');
    } catch (error) {
      res.setHeader('Set-Cookie', clearCookie(cookie.login, secure));
      if (error instanceof TokenRejectedError) {
        return sendPage(res, 401, (nonce) => rejectedPage(nonce, app, error.code, error.message));
      }
      if (error instanceof oidc.AuthorizationResponseError) {
        const reason = error.error_description ?? error.error;
        return sendPage(res, 400, (nonce) => rejectedPage(nonce, app, error.error, reason));
      }
      throw error;
    }
  }

  function showHome(req: IncomingMessage, res: ServerResponse) {
    const cookies = readCookies(req);
    const session = sessions.get(cookies.get(cookie.session) ?? '');
    if (!session || session.expiresAt < Date.now()) {
      return sendPage(res, 200, (nonce) => signedOutPage(nonce, app, options.issuer));
    }
    return sendPage(res, 200, (nonce) =>
      signedInPage({
        nonce,
        app,
        claims: session.claims,
        token: session.token,
        measurement: session.measurement,
        experiment: {
          cookieBytes: session.measurement.cookieBytes,
          keptByBrowser: cookies.get(cookie.naiveToken) === session.token,
        },
        otherAppUrl: options.otherAppUrl,
      }),
    );
  }

  function logout(req: IncomingMessage, res: ServerResponse) {
    sessions.delete(readCookies(req).get(cookie.session) ?? '');
    res.setHeader('Set-Cookie', [clearCookie(cookie.session, secure), clearCookie(cookie.naiveToken, secure)]);
    redirect(res, '/');
  }

  async function handler(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '/', baseUrl);
    try {
      if (url.pathname === '/healthz') return void res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok');
      if (url.pathname === '/' && req.method === 'GET') return showHome(req, res);
      if (url.pathname === '/login' && req.method === 'GET') return await startLogin(res);
      if (url.pathname === '/callback' && req.method === 'GET') return await finishLogin(req, res, url);
      if (url.pathname === '/logout' && req.method === 'POST') return logout(req, res);
      res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not found');
    } catch (error) {
      console.error(`[${app.clientId}] request failed`, error);
      if (!res.headersSent) {
        sendPage(res, 502, (nonce) =>
          rejectedPage(nonce, app, 'provider-unavailable', 'Could not complete sign-in with the identity provider.'),
        );
      }
    }
  }

  return { handler };
}

function randomId(): string {
  return randomBytes(24).toString('base64url');
}

function redirect(res: ServerResponse, location: string) {
  res.writeHead(303, { Location: location, 'Cache-Control': 'no-store' }).end();
}

function sendPage(res: ServerResponse, status: number, render: (nonce: string) => string) {
  const nonce = randomBytes(16).toString('base64');
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders(nonce) });
  res.end(render(nonce));
}

/** Sends back-channel requests for `publicBase` to `internalBase` instead (see RpAppOptions.internalIssuer). */
function rewritingFetch(publicBase: string, internalBase: string | undefined): typeof fetch {
  if (!internalBase || internalBase === publicBase) return fetch;
  return (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    const target = url.startsWith(publicBase) ? internalBase + url.slice(publicBase.length) : url;
    return fetch(target, init);
  };
}
