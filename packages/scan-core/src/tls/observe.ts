/**
 * Sends one ClientHello to a pinned target and returns what the server showed.
 * One call is one TCP connection. The connection is closed as soon as the
 * server's flight has been read; nothing is sent after the ClientHello.
 */
import { connectPinned, ConnectError } from '../net/connect.ts';
import type { PinnedTarget } from '../net/resolve.ts';
import { buildClientHello } from './clienthello.ts';
import type { ClientHelloSpec } from './clienthello.ts';
import { HandshakeObserver } from './handshake.ts';
import type { HandshakeObservation } from './handshake.ts';
import { CONTENT_TYPE, record } from './wire.ts';

export interface ObserveOptions {
  connectTimeoutMs?: number;
  /** Time allowed for the server's whole flight after the ClientHello is sent. */
  handshakeTimeoutMs?: number;
  /** Epoch milliseconds after which the scan as a whole is out of time. */
  deadline?: number;
}

/** A server's flight is a few kilobytes; ML-DSA chains reach tens. Past this the peer is not behaving like a TLS server. */
const MAX_BYTES = 512 * 1024;

export type ProbeSpec = Omit<ClientHelloSpec, 'serverName'>;

export async function observeHandshake(pinned: PinnedTarget, spec: ProbeSpec, options: ObserveOptions = {}): Promise<HandshakeObservation> {
  const left = (options.deadline ?? Infinity) - Date.now();
  if (left <= 0) return { outcome: 'timeout', detail: 'the scan ran out of time before this handshake' };
  let socket;
  try {
    socket = await connectPinned(pinned, Math.min(options.connectTimeoutMs ?? 5000, left));
  } catch (error) {
    if (error instanceof ConnectError) return { outcome: 'unreachable', detail: error.message };
    throw error;
  }

  const hello = buildClientHello({ ...spec, serverName: pinned.hasHostname ? pinned.hostname : undefined });
  const observer = new HandshakeObserver(hello, spec.keyShares);

  return new Promise<HandshakeObservation>((resolve) => {
    let received = 0;
    const finish = () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(observer.observation);
    };
    const timer = setTimeout(() => {
      observer.end('timeout');
      finish();
    }, Math.min(options.handshakeTimeoutMs ?? 6000, left));

    socket.on('data', (chunk: Buffer) => {
      received += chunk.length;
      if (received > MAX_BYTES) observer.end('closed', 'the server sent more data than a TLS handshake needs');
      else observer.push(chunk);
      if (observer.done) finish();
    });
    socket.on('error', (error: NodeJS.ErrnoException) => {
      observer.end('closed', error.code === 'ECONNRESET' ? 'the server reset the connection' : error.message);
      finish();
    });
    socket.on('close', () => {
      observer.end('closed');
      finish();
    });

    // The record version of a first ClientHello is 0x0301 for compatibility (RFC 8446 §5.1).
    socket.write(record(CONTENT_TYPE.handshake, 0x0301, hello.message));
  });
}
