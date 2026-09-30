import type { IncomingMessage, ServerResponse } from 'node:http';
import Provider from 'oidc-provider';
import type { DemoClient } from './clients.ts';
import { createConfiguration } from './config.ts';
import { createInteractionHandler, sendHtml } from './interactions.ts';
import type { PrivateJwks } from './keys.ts';
import { errorPage, landingPage } from './views.ts';

export interface ProviderAppOptions {
  /** The public URL browsers and apps use to reach the provider, e.g. http://localhost:3000. */
  issuer: string;
  clients: DemoClient[];
  jwks: PrivateJwks;
  cookieKeys?: string[];
  /** Trust X-Forwarded-* headers (set when running behind an ingress or load balancer). */
  trustProxy?: boolean;
}

/**
 * Builds the provider as a plain Node request handler:
 *   /                 landing page listing the registered apps
 *   /healthz          liveness/readiness probe for Kubernetes
 *   /interaction/...  our login UI
 *   everything else   oidc-provider (discovery, /auth, /token, /jwks, ...)
 */
export function createProviderApp(options: ProviderAppOptions) {
  const provider = new Provider(options.issuer, createConfiguration(options));
  provider.proxy = options.trustProxy ?? false;

  const handleInteraction = createInteractionHandler(provider, options.clients);
  const handleOidc = provider.callback();

  async function handler(req: IncomingMessage, res: ServerResponse) {
    const { pathname } = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (pathname === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok');
      } else if (pathname === '/' && req.method === 'GET') {
        sendHtml(res, 200, (nonce) => landingPage(nonce, options.issuer, options.clients));
      } else if (pathname.startsWith('/interaction/')) {
        await handleInteraction(req, res, pathname);
      } else {
        await handleOidc(req, res);
      }
    } catch (error) {
      console.error('Request failed', { path: pathname, error: error instanceof Error ? error.message : error });
      if (!res.headersSent) {
        sendHtml(res, 400, (nonce) => errorPage(nonce, 'invalid_request', 'This sign-in link is no longer valid.'));
      }
    }
  }

  return { provider, handler };
}
