import { createServer } from 'node:http';
import { createRpApp } from './app.ts';
import { isPresetName, PRESETS } from './presets.ts';

/**
 * Starts one demo app. RP_PRESET picks which one: "legacy" or "pq".
 */
const env = process.env;
if (!isPresetName(env.RP_PRESET)) {
  throw new Error('Set RP_PRESET to "legacy" or "pq"');
}
const preset = PRESETS[env.RP_PRESET];
const port = Number(env.PORT ?? preset.defaultPort);
const baseUrl = env.BASE_URL ?? `http://localhost:${port}`;

const { handler } = createRpApp({
  preset,
  baseUrl,
  clientSecret: env.CLIENT_SECRET ?? `${preset.clientId}-demo-secret`,
  issuer: env.ISSUER ?? 'http://localhost:3000',
  internalIssuer: env.INTERNAL_ISSUER,
  otherAppUrl: env.OTHER_APP_URL,
});

const server = createServer(handler);
server.listen(port, () => {
  console.log(`${preset.appName} listening on ${baseUrl} (accepts ${preset.acceptedAlgs.join(', ')})`);
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
