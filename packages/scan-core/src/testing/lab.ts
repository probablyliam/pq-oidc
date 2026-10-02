/**
 * Local HTTPS servers with deliberately different TLS, certificate and
 * sign-in configurations, so the scanner can be tested and demonstrated
 * without touching anyone else's systems. Each is a real OpenSSL (Node) TLS
 * server; the scanner's own handshake code is tested against that independent
 * implementation.
 *
 * `npm run lab` starts them on fixed ports; tests start them on random ports.
 */
import crypto from 'node:crypto';
import https from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { SecureVersion } from 'node:tls';
import { issueCertificate } from './certs.ts';
import type { Certificate, KeySpec } from './certs.ts';

export interface LabProfile {
  id: string;
  /** What this server is, in a few words. */
  title: string;
  /** Fixed port used by `npm run lab`. */
  port: number;
  tls: {
    /** OpenSSL group list, most preferred first. */
    groups?: string;
    minVersion?: SecureVersion;
    maxVersion?: SecureVersion;
    /** OpenSSL cipher string for TLS 1.2. */
    ciphers?: string;
  };
  certificate: {
    key: KeySpec;
    /** No CA: the leaf signs itself. */
    selfSigned?: boolean;
    expired?: boolean;
  };
  site: {
    hsts?: string;
    setCookie?: string;
    /** Publish OIDC metadata and a JWKS with a key for this algorithm. */
    oidcAlg?: 'ES256' | 'RS256' | 'ML-DSA-65';
  };
}

export const LAB_PROFILES: readonly LabProfile[] = [
  {
    id: 'classical',
    title: 'Classical key exchange, ECDSA certificate, ES256 tokens',
    port: 9441,
    tls: { groups: 'X25519:P-256:P-384' },
    certificate: { key: { type: 'ec', curve: 'P-256' } },
    site: { hsts: 'max-age=31536000; includeSubDomains', setCookie: 'session=abc; Path=/; Secure; HttpOnly; SameSite=Lax', oidcAlg: 'ES256' },
  },
  {
    id: 'hybrid',
    title: 'Hybrid key exchange offered, classical still accepted, RSA-signed tokens',
    port: 9442,
    tls: { groups: 'X25519MLKEM768:X25519:P-256' },
    certificate: { key: { type: 'ec', curve: 'P-256' } },
    site: { hsts: 'max-age=31536000', setCookie: 'session=abc; Path=/; Secure; HttpOnly; SameSite=Lax', oidcAlg: 'RS256' },
  },
  {
    id: 'hybrid-only',
    title: 'Hybrid key exchange required: clients without ML-KEM cannot connect',
    port: 9443,
    tls: { groups: 'X25519MLKEM768:SecP256r1MLKEM768', minVersion: 'TLSv1.3' },
    certificate: { key: { type: 'ec', curve: 'P-384' } },
    site: { hsts: 'max-age=31536000' },
  },
  {
    id: 'pq',
    title: 'Post-quantum throughout: ML-KEM key exchange, ML-DSA-65 certificate chain and tokens',
    port: 9444,
    tls: { groups: 'X25519MLKEM768:SecP384r1MLKEM1024:MLKEM1024:MLKEM768', minVersion: 'TLSv1.3' },
    certificate: { key: { type: 'ml-dsa-65' } },
    site: { hsts: 'max-age=31536000', setCookie: 'session=abc; Path=/; Secure; HttpOnly; SameSite=Strict', oidcAlg: 'ML-DSA-65' },
  },
  {
    id: 'tls12',
    title: 'TLS 1.2 only, RSA certificate, no HSTS, cookie without Secure',
    port: 9445,
    tls: { groups: 'P-256', maxVersion: 'TLSv1.2' },
    certificate: { key: { type: 'rsa', bits: 2048 } },
    site: { setCookie: 'session=abc; Path=/' },
  },
  {
    id: 'rsa-kex',
    title: 'TLS 1.2 with RSA key transport: no forward secrecy',
    port: 9446,
    tls: { maxVersion: 'TLSv1.2', ciphers: 'AES256-GCM-SHA384' },
    certificate: { key: { type: 'rsa', bits: 2048 } },
    site: {},
  },
  {
    id: 'expired',
    title: 'Expired, self-signed certificate',
    port: 9447,
    tls: {},
    certificate: { key: { type: 'ec', curve: 'P-256' }, selfSigned: true, expired: true },
    site: {},
  },
];

export function labProfile(id: string): LabProfile {
  const profile = LAB_PROFILES.find((p) => p.id === id);
  if (!profile) throw new Error(`No lab profile "${id}"`);
  return profile;
}

export interface LabServer {
  profile: LabProfile;
  origin: string;
  port: number;
  /** The chain the server presents, leaf first. */
  chain: Certificate[];
  /** Paths requested since start, for tests that assert what the scanner did and did not fetch. */
  requests: string[];
  close(): Promise<void>;
}

/** One root and one intermediate per key family, shared by every server in the process. */
const authorities = new Map<string, { root: Certificate; intermediate: Certificate }>();

function authorityFor(key: KeySpec) {
  const family = key.type.startsWith('ml-dsa') ? 'ml-dsa' : key.type;
  let authority = authorities.get(family);
  if (!authority) {
    const caKey: KeySpec = family === 'ml-dsa' ? { type: 'ml-dsa-65' } : family === 'rsa' ? { type: 'rsa', bits: 2048 } : { type: 'ec', curve: 'P-384' };
    const root = issueCertificate({ subject: `pq-oidc lab root (${family})`, key: caKey, ca: true });
    const intermediate = issueCertificate({ subject: `pq-oidc lab issuing CA (${family})`, key: caKey, ca: true, issuer: root });
    authority = { root, intermediate };
    authorities.set(family, authority);
  }
  return authority;
}

function certificateChain(profile: LabProfile): Certificate[] {
  const names = ['localhost', '127.0.0.1', '::1'];
  const validity = profile.certificate.expired
    ? { notBefore: new Date(Date.now() - 40 * 86_400_000), notAfter: new Date(Date.now() - 10 * 86_400_000) }
    : {};
  const subject = `${profile.id}.lab.localhost`;
  if (profile.certificate.selfSigned) return [issueCertificate({ subject, key: profile.certificate.key, names, ...validity })];
  const { intermediate } = authorityFor(profile.certificate.key);
  return [issueCertificate({ subject, key: profile.certificate.key, names, issuer: intermediate, ...validity }), intermediate];
}

const TOKEN_KEYS = {
  ES256: () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }),
  RS256: () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }),
  'ML-DSA-65': () => crypto.generateKeyPairSync('ml-dsa-65' as 'ed25519'),
} as const;

function tokenJwks(alg: NonNullable<LabProfile['site']['oidcAlg']>) {
  const { publicKey } = TOKEN_KEYS[alg]();
  const jwk = publicKey.export({ format: 'jwk' });
  return { keys: [{ ...jwk, alg, use: 'sig', kid: `lab-${alg.toLowerCase()}-1` }] };
}

const LOGIN_PAGE = `<!doctype html><meta charset="utf-8"><title>Lab sign-in</title>
<form method="post" action="/login"><label>Username <input name="username"></label>
<label>Password <input name="password" type="password"></label><button>Sign in</button></form>`;

export async function startLabServer(profile: LabProfile, port = 0): Promise<LabServer> {
  const chain = certificateChain(profile);
  const jwks = profile.site.oidcAlg ? tokenJwks(profile.site.oidcAlg) : undefined;
  const requests: string[] = [];
  let origin = '';

  const handler = (req: IncomingMessage, res: ServerResponse) => {
    const path = req.url ?? '/';
    requests.push(path);
    const send = (status: number, type: string, body: string, headers: Record<string, string> = {}) => {
      res.writeHead(status, { 'content-type': type, ...headers }).end(body);
    };
    const redirect = (location: string) => send(302, 'text/plain', 'redirecting', { location });
    const json = (value: unknown) => send(200, 'application/json', JSON.stringify(value));

    if (path === '/' || path.startsWith('/login') || path.startsWith('/authorize')) {
      const headers: Record<string, string> = {};
      if (profile.site.hsts) headers['strict-transport-security'] = profile.site.hsts;
      if (profile.site.setCookie) headers['set-cookie'] = profile.site.setCookie;
      return send(200, 'text/html; charset=utf-8', LOGIN_PAGE, headers);
    }
    if (path === '/.well-known/openid-configuration' && jwks) {
      return json({
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        jwks_uri: `${origin}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: [profile.site.oidcAlg],
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (path === '/jwks' && jwks) return json(jwks);

    // Things a hostile or broken target might do to a scanner.
    if (path === '/redirect/metadata') return redirect('https://169.254.169.254/latest/meta-data/iam/security-credentials/');
    if (path === '/redirect/loopback') return redirect('https://127.0.0.1:8443/admin');
    if (path === '/redirect/internal-name') return redirect('https://wiki.corp/secret');
    if (path === '/redirect/plain-http') return redirect('http://example.com/');
    if (path === '/redirect/other-port') return redirect(`https://localhost:22/`);
    if (path === '/redirect/loop') return redirect('/redirect/loop');
    if (path === '/redirect/once') return redirect('/');
    if (path === '/slow') return; // never answers
    if (path === '/big') {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      const chunk = Buffer.alloc(64 * 1024, 0x61);
      const write = () => {
        while (!res.destroyed && res.write(chunk));
        if (!res.destroyed) res.once('drain', write);
      };
      return write();
    }
    return send(404, 'text/plain', 'not found');
  };

  const server = https.createServer(
    {
      key: chain[0]!.keyPem,
      cert: chain.map((c) => c.certPem).join(''),
      ecdhCurve: profile.tls.groups,
      minVersion: profile.tls.minVersion,
      maxVersion: profile.tls.maxVersion,
      ciphers: profile.tls.ciphers,
    },
    handler,
  );
  // A scanner hangs up mid-handshake by design; that is not an error worth reporting.
  server.on('tlsClientError', () => {});
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  const actualPort = (server.address() as AddressInfo).port;
  origin = `https://localhost:${actualPort}`;

  return {
    profile,
    origin,
    port: actualPort,
    chain,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
