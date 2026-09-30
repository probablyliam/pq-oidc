import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createProviderApp, generateSigningKeys } from '@pq-oidc/provider';
import type { DemoClient, PrivateJwks, ProviderSigningAlg } from '@pq-oidc/provider';
import { createRpApp, PRESETS } from '@pq-oidc/rp';

export interface Stack {
  issuer: string;
  legacyUrl: string;
  pqUrl: string;
  clients: DemoClient[];
  close: () => Promise<void>;
}

export interface StackOptions {
  legacyAlg?: ProviderSigningAlg;
  pqAlg?: ProviderSigningAlg;
  jwks?: PrivateJwks;
  /**
   * Make the apps reach the provider on a different address than browsers do,
   * like containers in Docker or Kubernetes (here: localhost vs 127.0.0.1).
   */
  splitHorizon?: boolean;
}

async function listen(): Promise<{ server: Server; url: string }> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { server, url: `http://127.0.0.1:${port}` };
}

/**
 * Starts the provider and both demo apps in this process on random ports,
 * wired together exactly like `npm start` does.
 */
export async function startStack(options: StackOptions = {}): Promise<Stack> {
  // Bind ports first: each component needs the others' URLs in its config.
  const [provider, legacy, pq] = await Promise.all([listen(), listen(), listen()]);

  const clients: DemoClient[] = [
    {
      clientId: 'legacy-app',
      clientSecret: 'legacy-secret',
      name: 'Legacy App',
      redirectUri: `${legacy.url}/callback`,
      idTokenAlg: options.legacyAlg ?? 'ES256',
    },
    {
      clientId: 'pq-app',
      clientSecret: 'pq-secret',
      name: 'PQ-Ready App',
      redirectUri: `${pq.url}/callback`,
      idTokenAlg: options.pqAlg ?? 'ML-DSA-65',
    },
  ];

  const providerApp = createProviderApp({
    issuer: provider.url,
    clients,
    jwks: options.jwks ?? (await generateSigningKeys()),
  });
  provider.server.on('request', providerApp.handler);

  const internalIssuer = options.splitHorizon ? provider.url.replace('127.0.0.1', 'localhost') : undefined;
  legacy.server.on(
    'request',
    createRpApp({ preset: PRESETS.legacy, clientSecret: 'legacy-secret', baseUrl: legacy.url, issuer: provider.url, internalIssuer })
      .handler,
  );
  pq.server.on(
    'request',
    createRpApp({ preset: PRESETS.pq, clientSecret: 'pq-secret', baseUrl: pq.url, issuer: provider.url, internalIssuer }).handler,
  );

  return {
    issuer: provider.url,
    legacyUrl: legacy.url,
    pqUrl: pq.url,
    clients,
    close: async () => {
      await Promise.all(
        [provider, legacy, pq].map(({ server }) => {
          server.closeAllConnections(); // don't wait for idle keep-alive sockets
          return new Promise<void>((resolve) => server.close(() => resolve()));
        }),
      );
    },
  };
}
