import net from 'node:net';
import type { PinnedTarget } from './resolve.ts';

/** A network failure in a form the report can show. */
export class ConnectError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'ConnectError';
    this.code = code;
  }
}

/**
 * Opens a TCP connection to the pinned address. `host` is always an IP
 * literal, so Node never performs a DNS lookup here; the `lookup` override
 * turns any future mistake into an error instead of a second resolution.
 */
export function connectPinned(pinned: PinnedTarget, timeoutMs: number): Promise<net.Socket> {
  if (net.isIP(pinned.address) === 0) {
    return Promise.reject(new ConnectError('not-pinned', 'Refusing to connect: the target is not pinned to an IP address.'));
  }
  return new Promise((resolve, reject) => {
    const socket = net.connect({
      host: pinned.address,
      port: pinned.port,
      family: pinned.family,
      lookup: () => {
        throw new ConnectError('not-pinned', 'Unexpected DNS lookup for a pinned target.');
      },
    });
    socket.setNoDelay(true);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new ConnectError('connect-timeout', `No answer from ${pinned.address}:${pinned.port} within ${timeoutMs} ms.`));
    }, timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once('error', (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(new ConnectError(error.code ?? 'connect-failed', describe(error, pinned)));
    });
  });
}

function describe(error: NodeJS.ErrnoException, pinned: PinnedTarget): string {
  const where = `${pinned.address}:${pinned.port}`;
  switch (error.code) {
    case 'ECONNREFUSED':
      return `${where} refused the connection.`;
    case 'ECONNRESET':
      return `${where} reset the connection.`;
    case 'EHOSTUNREACH':
    case 'ENETUNREACH':
      return `${where} is unreachable from here.`;
    default:
      return `Could not connect to ${where}: ${error.message}`;
  }
}
