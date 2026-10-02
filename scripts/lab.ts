/**
 * `npm run lab`: starts the local test servers on fixed ports, each with a
 * different TLS, certificate and sign-in configuration, so there is something
 * to scan that is yours.
 *
 * The scanner refuses loopback addresses by default. `npm start` allows
 * exactly these origins through SCAN_LAB_ORIGINS.
 */
import { LAB_PROFILES, startLabServer } from '@pq-oidc/scan-core/testing';

export const LAB_ORIGINS = LAB_PROFILES.map((profile) => `https://localhost:${profile.port}`);

if (import.meta.main) {
  for (const profile of LAB_PROFILES) {
    const server = await startLabServer(profile, profile.port);
    console.log(`${server.origin.padEnd(26)} ${profile.title}`);
  }
  console.log('\nLab servers running. Press Ctrl+C to stop.');
}
