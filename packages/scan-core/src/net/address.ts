/**
 * Decides whether an IP address is one the scanner may connect to.
 *
 * This is the SSRF boundary (ADR 0007): hostnames are never trusted, only the
 * addresses they resolve to. The tables follow the IANA special-purpose
 * registries (RFC 6890 and updates). IPv6 forms that carry an IPv4 address
 * (mapped, NAT64, 6to4) are judged by the address inside them.
 *
 * No dependencies and no Node APIs, so the API can give the same answer for an
 * IP-literal target before a job is ever queued.
 */

export interface AddressVerdict {
  address: string;
  family: 4 | 6;
  allowed: boolean;
  /** Why not, e.g. "loopback (127.0.0.0/8)". */
  reason?: string;
  /** The IPv4 address carried inside an IPv6 form, when there is one. */
  embeddedIpv4?: string;
}

const IPV4_BLOCKED: [cidr: string, name: string][] = [
  ['0.0.0.0/8', 'this network'],
  ['10.0.0.0/8', 'private'],
  ['100.64.0.0/10', 'carrier-grade NAT'],
  ['127.0.0.0/8', 'loopback'],
  ['169.254.0.0/16', 'link-local, including cloud metadata services'],
  ['172.16.0.0/12', 'private'],
  ['192.0.0.0/24', 'IETF protocol assignments'],
  ['192.0.2.0/24', 'documentation'],
  ['192.88.99.0/24', 'deprecated 6to4 relay'],
  ['192.168.0.0/16', 'private'],
  ['198.18.0.0/15', 'benchmarking'],
  ['198.51.100.0/24', 'documentation'],
  ['203.0.113.0/24', 'documentation'],
  ['224.0.0.0/4', 'multicast'],
  ['240.0.0.0/4', 'reserved, including broadcast'],
];

const IPV6_BLOCKED: [cidr: string, name: string][] = [
  ['::/128', 'unspecified'],
  ['::1/128', 'loopback'],
  ['::/96', 'deprecated IPv4-compatible'],
  ['64:ff9b:1::/48', 'local-use NAT64'],
  ['100::/64', 'discard-only'],
  ['2001::/23', 'IETF protocol assignments, including Teredo'],
  ['2001:db8::/32', 'documentation'],
  ['3fff::/20', 'documentation'],
  ['5f00::/16', 'segment routing'],
  ['fc00::/7', 'unique local, including cloud metadata services'],
  ['fe80::/10', 'link-local'],
  ['fec0::/10', 'deprecated site-local'],
  ['ff00::/8', 'multicast'],
];

/** IPv6 prefixes that wrap an IPv4 address, and where in the 16 bytes it sits. */
const IPV6_EMBEDS_IPV4: [cidr: string, name: string, offset: number][] = [
  ['::ffff:0:0/96', 'IPv4-mapped', 12],
  ['64:ff9b::/96', 'NAT64', 12],
  ['2002::/16', '6to4', 2],
];

/** Strict dotted decimal: four octets, no leading zeros, nothing else. */
export function parseIpv4(text: string): Uint8Array | undefined {
  const parts = text.split('.');
  if (parts.length !== 4) return undefined;
  const bytes = new Uint8Array(4);
  for (const [i, part] of parts.entries()) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return undefined;
    const value = Number(part);
    if (value > 255) return undefined;
    bytes[i] = value;
  }
  return bytes;
}

/** RFC 4291 text forms, including `::` and a dotted IPv4 tail. Zone IDs are refused. */
export function parseIpv6(text: string): Uint8Array | undefined {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || !text.includes(':')) return undefined;
  const halves = text.split('::');
  if (halves.length > 2) return undefined;

  const groups = (part: string): number[] | undefined => {
    if (part === '') return [];
    const out: number[] = [];
    const pieces = part.split(':');
    for (const [i, piece] of pieces.entries()) {
      if (piece.includes('.')) {
        const v4 = i === pieces.length - 1 ? parseIpv4(piece) : undefined;
        if (!v4) return undefined;
        out.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return undefined;
        out.push(parseInt(piece, 16));
      }
    }
    return out;
  };

  const head = groups(halves[0]!);
  const tail = halves.length === 2 ? groups(halves[1]!) : [];
  if (!head || !tail) return undefined;
  // A dotted tail is only valid at the very end of the address.
  if (halves.length === 2 && halves[0]!.includes('.')) return undefined;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;

  const all = [...head, ...new Array<number>(halves.length === 2 ? missing : 0).fill(0), ...tail];
  const bytes = new Uint8Array(16);
  for (const [i, group] of all.entries()) {
    bytes[i * 2] = group >> 8;
    bytes[i * 2 + 1] = group & 0xff;
  }
  return bytes;
}

interface Prefix {
  bytes: Uint8Array;
  bits: number;
}

function parsePrefix(cidr: string): Prefix {
  const [address = '', bits = ''] = cidr.split('/');
  const bytes = parseIpv4(address) ?? parseIpv6(address);
  if (!bytes) throw new Error(`Bad prefix ${cidr}`);
  return { bytes, bits: Number(bits) };
}

function inPrefix(address: Uint8Array, prefix: Prefix): boolean {
  if (address.length !== prefix.bytes.length) return false;
  const whole = prefix.bits >> 3;
  for (let i = 0; i < whole; i++) if (address[i] !== prefix.bytes[i]) return false;
  const rest = prefix.bits & 7;
  if (rest === 0) return true;
  const mask = 0xff << (8 - rest);
  return (address[whole]! & mask) === (prefix.bytes[whole]! & mask);
}

const V4_TABLE = IPV4_BLOCKED.map(([cidr, name]) => ({ cidr, name, prefix: parsePrefix(cidr) }));
const V6_TABLE = IPV6_BLOCKED.map(([cidr, name]) => ({ cidr, name, prefix: parsePrefix(cidr) }));
const V6_EMBED_TABLE = IPV6_EMBEDS_IPV4.map(([cidr, name, offset]) => ({ cidr, name, offset, prefix: parsePrefix(cidr) }));
const GLOBAL_UNICAST = parsePrefix('2000::/3');

function blockedIpv4(bytes: Uint8Array): string | undefined {
  const hit = V4_TABLE.find((row) => inPrefix(bytes, row.prefix));
  return hit && `${hit.name} (${hit.cidr})`;
}

/**
 * Classifies one address. Anything that isn't a well-formed IPv4 or IPv6
 * address is refused, so a caller can't be tricked by a form this code reads
 * differently from the operating system.
 */
export function classifyAddress(input: string): AddressVerdict {
  const text = input.startsWith('[') && input.endsWith(']') ? input.slice(1, -1) : input;

  const v4 = parseIpv4(text);
  if (v4) {
    const reason = blockedIpv4(v4);
    return { address: text, family: 4, allowed: !reason, reason };
  }

  const v6 = parseIpv6(text);
  if (!v6) return { address: text, family: 6, allowed: false, reason: 'not a valid IP address' };
  const address = text.toLowerCase();

  for (const row of V6_EMBED_TABLE) {
    if (!inPrefix(v6, row.prefix)) continue;
    const inner = v6.slice(row.offset, row.offset + 4);
    const embeddedIpv4 = inner.join('.');
    const reason = blockedIpv4(inner);
    return {
      address,
      family: 6,
      allowed: !reason,
      embeddedIpv4,
      reason: reason && `${row.name} address for ${embeddedIpv4}: ${reason}`,
    };
  }

  const hit = V6_TABLE.find((row) => inPrefix(v6, row.prefix));
  if (hit) return { address, family: 6, allowed: false, reason: `${hit.name} (${hit.cidr})` };
  if (!inPrefix(v6, GLOBAL_UNICAST)) {
    return { address, family: 6, allowed: false, reason: 'outside global unicast space (2000::/3)' };
  }
  return { address, family: 6, allowed: true };
}

/** 4, 6, or 0 when `text` is not an IP literal (brackets allowed around IPv6). */
export function ipFamily(text: string): 0 | 4 | 6 {
  if (parseIpv4(text)) return 4;
  const bare = text.startsWith('[') && text.endsWith(']') ? text.slice(1, -1) : text;
  return parseIpv6(bare) ? 6 : 0;
}
