import {Buffer} from "buffer";
import {assert, readU32, qround, writeU32} from "./utils";

export class ChaCha20 {
  public static native = 0;

  private readonly BIG_ENDIAN = new Int8Array(new Int16Array([1]).buffer)[0] === 0;
  private state: Uint32Array;
  private stream: Uint32Array;
  private bytes: Uint8Array;
  private pos: number;

  constructor() {
    this.state = new Uint32Array(16);
    this.stream = new Uint32Array(16);
    this.bytes = new Uint8Array(this.stream.buffer);
    this.pos = -1;

    if (this.BIG_ENDIAN)
      this.bytes = Buffer.alloc(64);
  }

  /**
   * Initialize chacha20 with a key, nonce, and counter.
   * 
   * @param {Buffer} key
   * @param {Buffer} nonce
   * @param {Number} counter
   */
  public init(key: Buffer, nonce: Buffer, counter: number): this {
    if (counter == null)
      counter = 0;

    assert(Number.isSafeInteger(counter));

    if (key.length !== 16 && key.length !== 32)
      throw new RangeError('Invalid key size.');

    if (nonce.length >= 24) {
      key = ChaCha20.derive(key, nonce.slice(0, 16));
      nonce = nonce.slice(16);
    }

    this.state[0] = 0x61707865;
    this.state[1] = key.length < 32 ? 0x3120646e : 0x3320646e;
    this.state[2] = key.length < 32 ? 0x79622d36 : 0x79622d32;
    this.state[3] = 0x6b206574;
    this.state[4] = readU32(key, 0);
    this.state[5] = readU32(key, 4);
    this.state[6] = readU32(key, 8);
    this.state[7] = readU32(key, 12);
    this.state[8] = readU32(key, 16 % key.length);
    this.state[9] = readU32(key, 20 % key.length);
    this.state[10] = readU32(key, 24 % key.length);
    this.state[11] = readU32(key, 28 % key.length);
    this.state[12] = counter >>> 0;

    if (nonce.length === 8) {
      this.state[13] = (counter / 0x100000000) >>> 0;
      this.state[14] = readU32(nonce, 0);
      this.state[15] = readU32(nonce, 4);
    } else if (nonce.length === 12) {
      this.state[13] = readU32(nonce, 0);
      this.state[14] = readU32(nonce, 4);
      this.state[15] = readU32(nonce, 8);
    } else if (nonce.length === 16) {
      this.state[12] = readU32(nonce, 0);
      this.state[13] = readU32(nonce, 4);
      this.state[14] = readU32(nonce, 8);
      this.state[15] = readU32(nonce, 12);
    } else {
      throw new RangeError('Invalid nonce size.');
    }

    this.pos = 0;

    return this;
  }

  /**
   * Encrypt/decrypt data.
   * 
   * @param {Buffer} data - Will be mutated.
   * @returns {Buffer}
   */
  public encrypt(data: Buffer): Buffer {
    if (this.pos === -1)
      throw new Error('Context is not initialized.');

    for (let i = 0; i < data.length; i++) {
      if ((this.pos & 63) === 0) {
        this.block();
        this.pos = 0;
      }

      data[i] ^= this.bytes[this.pos++];
    }

    return data;
  }

  /**
   * Stir the stream.
   */
  private block(): void {
    for (let i = 0; i < 16; i++)
      this.stream[i] = this.state[i];

    for (let i = 0; i < 10; i++) {
      qround(this.stream, 0, 4, 8, 12);
      qround(this.stream, 1, 5, 9, 13);
      qround(this.stream, 2, 6, 10, 14);
      qround(this.stream, 3, 7, 11, 15);
      qround(this.stream, 0, 5, 10, 15);
      qround(this.stream, 1, 6, 11, 12);
      qround(this.stream, 2, 7, 8, 13);
      qround(this.stream, 3, 4, 9, 14);
    }

    for (let i = 0; i < 16; i++)
      this.stream[i] += this.state[i];

    if (this.BIG_ENDIAN) {
      for (let i = 0; i < 16; i++)
        writeU32(this.bytes, this.stream[i], i * 4);
    }

    this.state[12] += 1;

    if (this.state[12] === 0)
      this.state[13] += 1;
  }

  /**
   * Destroy context.
   */
  public destroy(): this {
    for (let i = 0; i < 16; i++) {
      this.state[i] = 0;
      this.stream[i] = 0;
    }

    if (this.BIG_ENDIAN) {
      for (let i = 0; i < 64; i++)
        this.bytes[i] = 0;
    }

    this.pos = -1;

    return this;
  }

  /**
   * Derive key with XChaCha20.
   * 
   * @param {Buffer} key
   * @param {Buffer} nonce
   * @returns {Buffer}
   */
  public static derive(key: Buffer, nonce: Buffer): Buffer {
    if (key.length !== 16 && key.length !== 32)
      throw new RangeError('Invalid key size.');

    if (nonce.length !== 16)
      throw new RangeError('Invalid nonce size.');

    const state = new Uint32Array(16);

    state[0] = 0x61707865;
    state[1] = key.length < 32 ? 0x3120646e : 0x3320646e;
    state[2] = key.length < 32 ? 0x79622d36 : 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = readU32(key, 0);
    state[5] = readU32(key, 4);
    state[6] = readU32(key, 8);
    state[7] = readU32(key, 12);
    state[8] = readU32(key, 16 % key.length);
    state[9] = readU32(key, 20 % key.length);
    state[10] = readU32(key, 24 % key.length);
    state[11] = readU32(key, 28 % key.length);
    state[12] = readU32(nonce, 0);
    state[13] = readU32(nonce, 4);
    state[14] = readU32(nonce, 8);
    state[15] = readU32(nonce, 12);

    for (let i = 0; i < 10; i++) {
      qround(state, 0, 4, 8, 12);
      qround(state, 1, 5, 9, 13);
      qround(state, 2, 6, 10, 14);
      qround(state, 3, 7, 11, 15);
      qround(state, 0, 5, 10, 15);
      qround(state, 1, 6, 11, 12);
      qround(state, 2, 7, 8, 13);
      qround(state, 3, 4, 9, 14);
    }

    const out = Buffer.alloc(32);

    writeU32(out, state[0], 0);
    writeU32(out, state[1], 4);
    writeU32(out, state[2], 8);
    writeU32(out, state[3], 12);
    writeU32(out, state[12], 16);
    writeU32(out, state[13], 20);
    writeU32(out, state[14], 24);
    writeU32(out, state[15], 28);

    return out;
  }
}
