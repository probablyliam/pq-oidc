/**
 * Reading and writing TLS's wire format: big-endian integers and
 * length-prefixed vectors. The reader is used on bytes from untrusted servers,
 * so every read is bounds-checked and a short buffer is an error, never a
 * silent truncation.
 */

/** The peer sent something that is not well-formed TLS. */
export class WireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WireError';
  }
}

export class Reader {
  private readonly data: Buffer;
  private offset = 0;

  constructor(data: Buffer) {
    this.data = data;
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }

  private need(n: number) {
    if (n > this.remaining) throw new WireError(`needed ${n} more bytes, ${this.remaining} left`);
  }

  u8(): number {
    this.need(1);
    return this.data[this.offset++]!;
  }

  u16(): number {
    this.need(2);
    const value = this.data.readUInt16BE(this.offset);
    this.offset += 2;
    return value;
  }

  u24(): number {
    this.need(3);
    const value = this.data.readUIntBE(this.offset, 3);
    this.offset += 3;
    return value;
  }

  bytes(n: number): Buffer {
    this.need(n);
    const out = this.data.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  /** A vector whose length is given by a prefix of 1, 2 or 3 bytes. */
  vector(prefixBytes: 1 | 2 | 3): Buffer {
    const length = prefixBytes === 1 ? this.u8() : prefixBytes === 2 ? this.u16() : this.u24();
    return this.bytes(length);
  }

  rest(): Buffer {
    return this.bytes(this.remaining);
  }
}

export class Writer {
  private readonly parts: Buffer[] = [];

  u8(value: number): this {
    this.parts.push(Buffer.from([value & 0xff]));
    return this;
  }

  u16(value: number): this {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(value);
    this.parts.push(b);
    return this;
  }

  u24(value: number): this {
    const b = Buffer.alloc(3);
    b.writeUIntBE(value, 0, 3);
    this.parts.push(b);
    return this;
  }

  bytes(value: Uint8Array): this {
    this.parts.push(Buffer.from(value));
    return this;
  }

  vector(prefixBytes: 1 | 2 | 3, value: Uint8Array | ((w: Writer) => void)): this {
    let body: Uint8Array;
    if (typeof value === 'function') {
      const inner = new Writer();
      value(inner);
      body = inner.finish();
    } else {
      body = value;
    }
    if (body.length >= 2 ** (8 * prefixBytes)) throw new RangeError('vector too long for its length prefix');
    if (prefixBytes === 1) this.u8(body.length);
    else if (prefixBytes === 2) this.u16(body.length);
    else this.u24(body.length);
    return this.bytes(body);
  }

  finish(): Buffer {
    return Buffer.concat(this.parts);
  }
}

export const CONTENT_TYPE = { changeCipherSpec: 20, alert: 21, handshake: 22, applicationData: 23 } as const;
export const HANDSHAKE_TYPE = {
  clientHello: 1,
  serverHello: 2,
  newSessionTicket: 4,
  encryptedExtensions: 8,
  certificate: 11,
  serverKeyExchange: 12,
  certificateRequest: 13,
  serverHelloDone: 14,
  certificateVerify: 15,
  finished: 20,
  certificateStatus: 22,
} as const;

export interface TlsRecord {
  type: number;
  version: number;
  /** The five header bytes, which are the additional data for TLS 1.3 record protection. */
  header: Buffer;
  fragment: Buffer;
}

/** A plaintext record may carry 2^14 bytes; a protected one 2^14 + 256 (RFC 8446 §5.2). */
const MAX_FRAGMENT = 16384 + 256;

/** Splits a TCP byte stream into TLS records. */
export class RecordReader {
  private pending: Buffer = Buffer.alloc(0);

  push(chunk: Buffer) {
    this.pending = this.pending.length ? Buffer.concat([this.pending, chunk]) : chunk;
  }

  /** The next complete record, or undefined if more bytes are needed. */
  next(): TlsRecord | undefined {
    if (this.pending.length < 5) return undefined;
    const type = this.pending[0]!;
    const version = this.pending.readUInt16BE(1);
    const length = this.pending.readUInt16BE(3);
    if (type < CONTENT_TYPE.changeCipherSpec || type > CONTENT_TYPE.applicationData || version >> 8 !== 3) {
      throw new WireError('the server did not answer with TLS');
    }
    if (length > MAX_FRAGMENT) throw new WireError(`record of ${length} bytes exceeds the TLS limit`);
    if (this.pending.length < 5 + length) return undefined;
    const record: TlsRecord = { type, version, header: this.pending.subarray(0, 5), fragment: this.pending.subarray(5, 5 + length) };
    this.pending = this.pending.subarray(5 + length);
    return record;
  }
}

export interface HandshakeMessage {
  type: number;
  body: Buffer;
  /** Header and body exactly as sent: this is what goes into the transcript hash. */
  raw: Buffer;
}

/** A sane ceiling for one handshake message; certificate chains with ML-DSA keys run to tens of kilobytes. */
const MAX_HANDSHAKE_MESSAGE = 256 * 1024;

/** Reassembles handshake messages, which may be split across records or share one. */
export class HandshakeReader {
  private pending: Buffer = Buffer.alloc(0);

  push(fragment: Buffer) {
    this.pending = this.pending.length ? Buffer.concat([this.pending, fragment]) : fragment;
  }

  next(): HandshakeMessage | undefined {
    if (this.pending.length < 4) return undefined;
    const length = this.pending.readUIntBE(1, 3);
    if (length > MAX_HANDSHAKE_MESSAGE) throw new WireError(`handshake message of ${length} bytes is larger than this scanner accepts`);
    if (this.pending.length < 4 + length) return undefined;
    const raw = this.pending.subarray(0, 4 + length);
    this.pending = this.pending.subarray(4 + length);
    return { type: raw[0]!, body: raw.subarray(4), raw };
  }

  get hasPartial(): boolean {
    return this.pending.length > 0;
  }
}

export function record(type: number, version: number, fragment: Uint8Array): Buffer {
  return new Writer().u8(type).u16(version).vector(2, fragment).finish();
}

export function handshakeMessage(type: number, body: Uint8Array): Buffer {
  return new Writer().u8(type).vector(3, body).finish();
}
