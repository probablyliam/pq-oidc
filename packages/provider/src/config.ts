import { randomBytes } from 'node:crypto';
import type { Configuration } from 'oidc-provider';
import { securityHeaders } from '@pq-oidc/token-kit';
import { findAccount } from './accounts.ts';
import { toClientMetadata } from './clients.ts';
import type { DemoClient } from './clients.ts';
import { SIGNING_ALGS } from './keys.ts';
import type { PrivateJwks } from './keys.ts';
import { errorPage, signedOutPage, signOutPage } from './views.ts';

export interface ConfigurationOptions {
  clients: DemoClient[];
  jwks: PrivateJwks;
  /** Keys that sign the provider's own cookies. Must be shared by all replicas. */
  cookieKeys?: string[];
}

/**
 * The provider's security policy in one place. Each setting below is a
 * deliberate choice that the threat model (docs/threat-model.md) refers to.
 */
export function createConfiguration({ clients, jwks, cookieKeys }: ConfigurationOptions): Configuration {
  return {
    clients: clients.map(toClientMetadata),
    jwks,
    findAccount,

    // OAuth 2.1 profile: authorization code flow only, PKCE (S256) required for every client.
    responseTypes: ['code'],
    pkce: { required: () => true },

    // The two algorithms this provider can sign ID tokens with.
    enabledJWA: {
      idTokenSigningAlgValues: [...SIGNING_ALGS],
    },

    // Put profile and email claims in the ID token itself, like most real
    // deployments do. This is also what makes the token-size problem realistic.
    conformIdTokenClaims: false,
    claims: {
      openid: ['sub'],
      profile: ['name', 'given_name', 'family_name'],
      email: ['email', 'email_verified'],
    },

    features: {
      devInteractions: { enabled: false }, // we render our own login page
      // RP-initiated logout: an app can end the provider's session too, not only its own.
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: (ctx, form) => {
          const nonce = randomBytes(16).toString('base64');
          ctx.set(securityHeaders(nonce));
          ctx.type = 'html';
          ctx.body = signOutPage(nonce, form);
        },
        postLogoutSuccessSource: (ctx) => {
          const nonce = randomBytes(16).toString('base64');
          ctx.set(securityHeaders(nonce));
          ctx.type = 'html';
          ctx.body = signedOutPage(nonce);
        },
      },
    },

    interactions: {
      url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
    },

    cookies: {
      keys: cookieKeys ?? [randomBytes(32).toString('base64url')],
    },

    // Short lifetimes: codes are single-use and die quickly, tokens last an hour.
    ttl: {
      AuthorizationCode: 60,
      IdToken: 3600,
      AccessToken: 600,
      Interaction: 600,
      Session: 8 * 3600,
      Grant: 8 * 3600,
    },

    // Show a friendly page instead of the library's default, without internals.
    renderError: (ctx, out) => {
      const nonce = randomBytes(16).toString('base64');
      ctx.set(securityHeaders(nonce));
      ctx.type = 'html';
      ctx.body = errorPage(nonce, String(out.error), out.error_description ? String(out.error_description) : undefined);
    },
  };
}
