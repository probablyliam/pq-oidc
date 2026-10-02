/**
 * Builds the ClientHello the scanner sends. What a server reveals depends on
 * what it is offered, so each probe is a different spec: which versions, which
 * groups, which of those groups come with a key share, and which signature
 * schemes.
 */
import { randomBytes } from 'node:crypto';
import type { KeyShare } from './keyshare.ts';
import { TLS12_SUITES, TLS13_SUITES } from './registry.ts';
import { HANDSHAKE_TYPE, handshakeMessage, Writer } from './wire.ts';

export interface ClientHelloSpec {
  /** Sent as SNI. Left out when the target is an IP address. */
  serverName?: string;
  versions: readonly ('1.3' | '1.2')[];
  /** supported_groups, most preferred first. */
  groups: readonly number[];
  /** Groups to send a key share for. Empty asks the server to name a group (HelloRetryRequest). */
  keyShares: readonly KeyShare[];
  signatureSchemes: readonly number[];
  alpn?: readonly string[];
  /** Fixed values, for tests. */
  random?: Buffer;
  sessionId?: Buffer;
}

export const EXTENSION = {
  serverName: 0,
  supportedGroups: 10,
  ecPointFormats: 11,
  signatureAlgorithms: 13,
  alpn: 16,
  extendedMasterSecret: 23,
  supportedVersions: 43,
  keyShare: 51,
  renegotiationInfo: 0xff01,
} as const;

export interface ClientHello {
  /** The handshake message (not yet wrapped in a record). */
  message: Buffer;
  random: Buffer;
}

export function buildClientHello(spec: ClientHelloSpec): ClientHello {
  const offers13 = spec.versions.includes('1.3');
  const offers12 = spec.versions.includes('1.2');
  const random = spec.random ?? randomBytes(32);
  const suites = [...(offers13 ? TLS13_SUITES : []), ...(offers12 ? TLS12_SUITES : [])];

  const extensions = new Writer();
  const extension = (type: number, body: (w: Writer) => void) => extensions.u16(type).vector(2, body);

  if (spec.serverName) {
    extension(EXTENSION.serverName, (w) => w.vector(2, (list) => list.u8(0).vector(2, Buffer.from(spec.serverName!, 'ascii'))));
  }
  extension(EXTENSION.supportedGroups, (w) => w.vector(2, (list) => spec.groups.forEach((g) => list.u16(g))));
  extension(EXTENSION.signatureAlgorithms, (w) => w.vector(2, (list) => spec.signatureSchemes.forEach((s) => list.u16(s))));
  if (spec.alpn?.length) {
    extension(EXTENSION.alpn, (w) => w.vector(2, (list) => spec.alpn!.forEach((name) => list.vector(1, Buffer.from(name, 'ascii')))));
  }
  if (offers12) {
    extension(EXTENSION.ecPointFormats, (w) => w.vector(1, Buffer.from([0])));
    extension(EXTENSION.extendedMasterSecret, () => {});
    extension(EXTENSION.renegotiationInfo, (w) => w.vector(1, Buffer.alloc(0)));
  }
  if (offers13) {
    extension(EXTENSION.supportedVersions, (w) =>
      w.vector(1, (list) => {
        list.u16(0x0304);
        if (offers12) list.u16(0x0303);
      }),
    );
    extension(EXTENSION.keyShare, (w) => w.vector(2, (shares) => spec.keyShares.forEach((share) => shares.u16(share.group).vector(2, share.publicBytes))));
  }

  const body = new Writer()
    .u16(0x0303) // legacy_version; the real offer is in supported_versions
    .bytes(random)
    .vector(1, spec.sessionId ?? randomBytes(32)) // a non-empty session ID asks for middlebox-compatibility mode
    .vector(2, (w) => suites.forEach((s) => w.u16(s)))
    .vector(1, Buffer.from([0])) // no compression
    .vector(2, extensions.finish())
    .finish();

  return { message: handshakeMessage(HANDSHAKE_TYPE.clientHello, body), random };
}
