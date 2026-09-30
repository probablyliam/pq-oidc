/**
 * Size limits a token runs into on its way through a typical web stack.
 * Each one is a documented default, not a guess.
 */
export interface SizeLimit {
  id: string;
  label: string;
  bytes: number;
  source: string;
}

export const SIZE_LIMITS: SizeLimit[] = [
  {
    id: 'cookie',
    label: 'One browser cookie',
    bytes: 4096,
    source: 'RFC 6265 §6.1; enforced as a maximum by Chrome, Firefox and Safari',
  },
  {
    id: 'nginx-header',
    label: 'One request header in nginx (default)',
    bytes: 8192,
    source: 'nginx large_client_header_buffers default: 4 8k',
  },
  {
    id: 'node-headers',
    label: 'All request headers in Node.js (default)',
    bytes: 16384,
    source: 'Node.js http.maxHeaderSize default: 16 KiB',
  },
];

/** Length of unpadded base64url for `n` raw bytes. */
export function base64urlLength(n: number): number {
  return Math.ceil((n * 4) / 3);
}
