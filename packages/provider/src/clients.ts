import type { ClientMetadata } from 'oidc-provider';
import type { ProviderSigningAlg } from './keys.ts';

/**
 * A registered app ("relying party"). The one field that matters for the
 * migration is `idTokenAlg`: changing it moves a single app to a new
 * signature algorithm without touching any other app.
 */
export interface DemoClient {
  clientId: string;
  clientSecret: string;
  name: string;
  redirectUri: string;
  idTokenAlg: ProviderSigningAlg;
}

export function toClientMetadata(client: DemoClient): ClientMetadata {
  return {
    client_id: client.clientId,
    client_secret: client.clientSecret,
    client_name: client.name,
    redirect_uris: [client.redirectUri],
    // OAuth 2.1: authorization code only. No implicit flow, no password grant.
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
    id_token_signed_response_alg: client.idTokenAlg,
  };
}

/** The two demo apps, configurable through environment variables. */
export function demoClientsFromEnv(env: NodeJS.ProcessEnv): DemoClient[] {
  return [
    {
      clientId: 'legacy-app',
      clientSecret: env.LEGACY_CLIENT_SECRET ?? 'legacy-app-demo-secret',
      name: 'Legacy App',
      redirectUri: env.LEGACY_REDIRECT_URI ?? 'http://localhost:3001/callback',
      idTokenAlg: parseAlg(env.LEGACY_ID_TOKEN_ALG, 'ES256'),
    },
    {
      clientId: 'pq-app',
      clientSecret: env.PQ_CLIENT_SECRET ?? 'pq-app-demo-secret',
      name: 'PQ-Ready App',
      redirectUri: env.PQ_REDIRECT_URI ?? 'http://localhost:3002/callback',
      idTokenAlg: parseAlg(env.PQ_ID_TOKEN_ALG, 'ML-DSA-65'),
    },
  ];
}

function parseAlg(value: string | undefined, fallback: ProviderSigningAlg): ProviderSigningAlg {
  if (value === undefined || value === '') return fallback;
  if (value === 'ES256' || value === 'ML-DSA-65') return value;
  throw new Error(`Unsupported ID token algorithm "${value}". Use ES256 or ML-DSA-65.`);
}
