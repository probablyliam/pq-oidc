/**
 * `npm run oidc`: runs the sign-in service and both demo apps locally, each in
 * its own process (the same way they run as separate containers in Kubernetes).
 *
 *   Provider      http://localhost:3000
 *   Legacy App    http://localhost:3001
 *   PQ-Ready App  http://localhost:3002
 *
 * Try moving Legacy App to post-quantum before it's ready:
 *   LEGACY_ID_TOKEN_ALG=ML-DSA-65 npm run oidc
 */
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';

const services = [
  { name: 'provider', color: 35, script: 'packages/provider/src/server.ts', env: { PORT: '3000' } },
  {
    name: 'legacy  ',
    color: 33,
    script: 'packages/rp/src/server.ts',
    env: { RP_PRESET: 'legacy', PORT: '3001', OTHER_APP_URL: 'http://localhost:3002/' },
  },
  {
    name: 'pq      ',
    color: 34,
    script: 'packages/rp/src/server.ts',
    env: { RP_PRESET: 'pq', PORT: '3002', OTHER_APP_URL: 'http://localhost:3001/' },
  },
];

const children: ChildProcess[] = services.map(({ name, color, script, env }) => {
  // Node marks its ML-DSA support as experimental; silence that one warning.
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', script], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const prefix = `\x1b[${color}m${name}\x1b[0m │ `;
  const print = (data: Buffer) => {
    for (const line of data.toString().trimEnd().split('\n')) console.log(prefix + line);
  };
  child.stdout?.on('data', print);
  child.stderr?.on('data', print);
  child.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      console.error(`${prefix}exited with code ${code}; stopping everything`);
      shutdown(1);
    }
  });
  return child;
});

setTimeout(() => {
  console.log('\nOpen http://localhost:3001 (Legacy App) or http://localhost:3002 (PQ-Ready App) and sign in.');
  console.log('Demo users: alice or bob, password quantum-safe. Press Ctrl+C to stop.\n');
}, 1500);

function shutdown(code = 0) {
  for (const child of children) child.kill();
  process.exit(code);
}
process.on('SIGINT', () => shutdown());
process.on('SIGTERM', () => shutdown());
