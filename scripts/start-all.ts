/**
 * `npm start`: runs the whole system locally, each part in its own process
 * (the same way they run as separate containers in Kubernetes).
 *
 *   Scanner (web app + API)  http://localhost:8080     sign in as alice or bob
 *   Worker                   no port: it claims jobs from the API
 *   Identity provider        http://localhost:3000
 *   Lab servers              https://localhost:9441-9447, things to scan
 *   Legacy App, PQ-Ready App http://localhost:3001, :3002 (the per-app migration demo)
 *
 * `npm run dev` is the same with the web app served by Vite on :5173 (hot reload).
 *
 * Try moving Legacy App to post-quantum before it's ready:
 *   LEGACY_ID_TOKEN_ALG=ML-DSA-65 npm start
 */
import { spawn, spawnSync } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { LAB_ORIGINS } from './lab.ts';

const dev = process.argv.includes('--dev');
const scannerUrl = dev ? 'http://localhost:5173' : 'http://localhost:8080';
const lab = LAB_ORIGINS.join(',');

interface Service {
  name: string;
  color: number;
  script: string;
  args?: string[];
  env: Record<string, string>;
}

const services: Service[] = [
  { name: 'provider', color: 35, script: 'packages/provider/src/server.ts', env: { PORT: '3000', SCANNER_URL: scannerUrl } },
  {
    name: 'api',
    color: 36,
    script: 'services/api/src/server.ts',
    env: { PORT: '8080', INTERNAL_PORT: '8081', PUBLIC_URL: scannerUrl, OIDC_ISSUER: 'http://localhost:3000', SCAN_LAB_ORIGINS: lab, ...(dev ? {} : { WEB_DIR: 'apps/web/dist' }) },
  },
  { name: 'worker', color: 32, script: 'services/worker/src/server.ts', env: { API_INTERNAL_URL: 'http://127.0.0.1:8081', SCAN_LAB_ORIGINS: lab } },
  { name: 'lab', color: 90, script: 'scripts/lab.ts', env: {} },
  { name: 'legacy', color: 33, script: 'packages/rp/src/server.ts', env: { RP_PRESET: 'legacy', PORT: '3001', OTHER_APP_URL: 'http://localhost:3002/' } },
  { name: 'pq', color: 34, script: 'packages/rp/src/server.ts', env: { RP_PRESET: 'pq', PORT: '3002', OTHER_APP_URL: 'http://localhost:3001/' } },
];

if (dev) {
  services.push({ name: 'web', color: 37, script: 'node_modules/vite/bin/vite.js', args: ['apps/web', '--port', '5173', '--strictPort'], env: {} });
} else if (!process.argv.includes('--no-build')) {
  console.log('Building the web app…');
  const build = spawnSync(process.execPath, ['node_modules/vite/bin/vite.js', 'build', 'apps/web', '--logLevel', 'warn'], { stdio: 'inherit' });
  if (build.status !== 0) process.exit(build.status ?? 1);
}

const width = Math.max(...services.map((s) => s.name.length));
const children: ChildProcess[] = services.map(({ name, color, script, args = [], env }) => {
  // Node marks its ML-DSA and SQLite support as experimental; silence that one warning.
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', script, ...args], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const prefix = `\x1b[${color}m${name.padEnd(width)}\x1b[0m │ `;
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
  console.log(`\nOpen ${scannerUrl} and sign in as alice or bob, password quantum-safe.`);
  console.log('Scan one of the lab servers (the "Try" links), or any public sign-in page. Press Ctrl+C to stop.\n');
}, 2500);

function shutdown(code = 0) {
  for (const child of children) child.kill();
  process.exit(code);
}
process.on('SIGINT', () => shutdown());
process.on('SIGTERM', () => shutdown());
