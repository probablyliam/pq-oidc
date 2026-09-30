import { randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import { securityHeaders } from '@pq-oidc/token-kit';
import { checkCredentials } from './accounts.ts';
import type { DemoClient } from './clients.ts';
import { loginPage } from './views.ts';

/**
 * oidc-provider handles the protocol; when it needs a human (to log in, or to
 * consent) it redirects the browser to /interaction/:uid and lets us render
 * the UI. The `_interaction` cookie ties the uid to this browser, which is what
 * stops another site from finishing someone else's login (CSRF).
 */
export function createInteractionHandler(provider: Provider, clients: DemoClient[]) {
  const clientById = new Map(clients.map((c) => [c.clientId, c]));

  return async function handleInteraction(req: IncomingMessage, res: ServerResponse, pathname: string) {
    const [, , uid, action] = pathname.split('/'); // "/interaction/:uid/:action?"
    const details = await provider.interactionDetails(req, res);
    if (details.uid !== uid) {
      throw new Error('Interaction does not match this browser session');
    }
    const client = clientById.get(String(details.params.client_id));

    // Consent: these apps are first-party, so we grant the requested scopes
    // automatically instead of showing a consent screen.
    if (details.prompt.name === 'consent') {
      const grant = details.grantId
        ? await provider.Grant.find(details.grantId)
        : new provider.Grant({ accountId: details.session?.accountId, clientId: String(details.params.client_id) });
      if (!grant) throw new Error('Grant not found');
      const missing = details.prompt.details as { missingOIDCScope?: string[]; missingOIDCClaims?: string[] };
      if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
      if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
      const grantId = await grant.save();
      return provider.interactionFinished(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
    }

    if (action === 'abort') {
      return provider.interactionFinished(
        req,
        res,
        { error: 'access_denied', error_description: 'The user cancelled the sign-in.' },
        { mergeWithLastSubmission: false },
      );
    }

    if (action === 'login' && req.method === 'POST') {
      const form = await readForm(req);
      const account = checkCredentials(form.get('username') ?? '', form.get('password') ?? '');
      if (!account) {
        return sendHtml(res, 401, (nonce) =>
          loginPage({ nonce, uid: details.uid, client, error: 'Wrong username or password.', username: form.get('username') ?? '' }),
        );
      }
      return provider.interactionFinished(req, res, { login: { accountId: account.id } }, { mergeWithLastSubmission: false });
    }

    return sendHtml(res, 200, (nonce) => loginPage({ nonce, uid: details.uid, client }));
  };
}

export function sendHtml(res: ServerResponse, status: number, render: (nonce: string) => string) {
  const nonce = randomBytes(16).toString('base64');
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders(nonce) });
  res.end(render(nonce));
}

const MAX_FORM_BYTES = 8 * 1024;

async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  if (!String(req.headers['content-type']).startsWith('application/x-www-form-urlencoded')) {
    throw new Error('Expected a form submission');
  }
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > MAX_FORM_BYTES) throw new Error('Form submission too large');
  }
  return new URLSearchParams(body);
}
