import {Buffer} from 'buffer';
import {assert, writeU64} from './utils';
import {ChaCha20} from './chacha20';
import {Poly1305} from './poly1305';

export class AEAD {
  public static native = ChaCha20.native;
  
  private chacha: ChaCha20;
  private poly: Poly1305;
  private key: Buffer;
  private mode: number;
  private aadLen: number;
  private cipherLen: number;
  
  constructor() {
    this.chacha = new ChaCha20();
    this.poly = new Poly1305();
    this.key = Buffer.alloc(64);
    this.mode = -1;
    this.aadLen = 0;
    this.cipherLen = 0;
  }

  /**
   * Initialize the AEAD with a key and iv.
   * 
   * @param {Buffer} key
   * @param {Buffer} iv - IV / packet sequence number.
   */
  public init(key: Buffer, iv: Buffer): this {
    this.key.fill(0x00);
    this.chacha.init(key, iv, 0);
    this.chacha.encrypt(this.key);
    this.poly.init(this.key);

    this.mode = 0;
    this.aadLen = 0;
    this.cipherLen = 0;

    return this;
  }

  /**
   * Update the aad (will be finalized
   * on an encrypt/decrypt call).
   * 
   * @param {Buffer} aad
   */
  public aad(data: Buffer): this {
    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    if (this.mode !== 0)
      throw new Error('Invalid state for aad.');

    this.poly.update(data);
    this.aadLen += data.length;

    return this;
  }

  /**
   * Encrypt a piece of data.
   * 
   * @param {Buffer} data
   */
  public encrypt(data: Buffer): Buffer {
    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    if (this.mode !== 0 && this.mode !== 1)
      throw new Error('Invalid state for encrypt.');

    if (this.mode === 0) {
      this.pad16(this.aadLen);
      this.mode = 1;
    }

    this.chacha.encrypt(data);
    this.poly.update(data);

    this.cipherLen += data.length;

    return data;
  }

  /**
   * Decrypt a piece of data.
   * 
   * @param {Buffer} data
   */
  public decrypt(data: Buffer): Buffer {
    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    if (this.mode !== 0 && this.mode !== 2)
      throw new Error('Invalid state for decrypt.');

    if (this.mode === 0) {
      this.pad16(this.aadLen);
      this.mode = 2;
    }

    this.cipherLen += data.length;

    this.poly.update(data);
    this.chacha.encrypt(data);

    return data;
  }

  /**
   * Authenticate data without decrypting.
   * 
   * @param {Buffer} data
   */
  public auth(data: Buffer): Buffer {
    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    if (this.mode !== 0 && this.mode !== 3)
      throw new Error('Invalid state for auth.');

    if (this.mode === 0) {
      this.pad16(this.aadLen);
      this.mode = 3;
    }

    this.cipherLen += data.length;

    this.poly.update(data);

    return data;
  }

  /**
   * Finalize the aead and generate a MAC.
   * @returns {Buffer} MAC
   */
  public final(): Buffer {
    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    const len = Buffer.allocUnsafe(16);

    writeU64(len, this.aadLen, 0);
    writeU64(len, this.cipherLen, 8);

    if (this.mode === 0)
      this.pad16(this.aadLen);

    this.pad16(this.cipherLen);
    this.poly.update(len);

    const mac: Buffer = this.poly.final();

    this.destroy();

    return mac;
  }

  /**
   * Destroy the context.
   */
  public destroy(): this {
    this.chacha.destroy();
    this.poly.destroy();

    for (let i = 0; i < 64; i++)
      this.key[i] = 0;

    this.mode = -1;
    this.aadLen = 0;
    this.cipherLen = 0;

    return this;
  }

  /**
   * Finalize and verify MAC against tag.
   * 
   * @param {Buffer} tag
   * @returns {Boolean}
   */
  public verify(tag: Buffer): boolean {
    assert(tag.length === 16);

    const mac = this.final();

    let z = 0;

    for (let i = 0; i < 16; i++)
      z |= mac[i] ^ tag[i];

    return ((z - 1) >>> 31) !== 0;
  }

  /**
   * Pad a chunk before updating mac.
   *
   * @param {Number} size
   */
  private pad16(size: number): void {
    const pos = size & 15;

    if (pos === 0)
      return;

    const pad = Buffer.allocUnsafe(16 - pos);

    pad.fill(0x00);

    this.poly.update(pad);
  }

  /**
   * Encrypt a piece of data.
   * 
   * @param {Buffer} key
   * @param {Buffer} iv
   * @param {Buffer} msg
   * @param {Buffer?} aad
   * @returns {Buffer} tag
   */
  public static encrypt(key: Buffer, iv: Buffer, msg: Buffer, aad?: Buffer): Buffer {
    const aead = new AEAD();

    aead.init(key, iv);

    if (aad)
      aead.aad(aad);

    aead.encrypt(msg);

    return aead.final();
  }

  /**
   * Decrypt a piece of data.
   * 
   * @param {Buffer} key
   * @param {Buffer} iv
   * @param {Buffer} msg
   * @param {Buffer} tag
   * @param {Buffer?} aad
   * @returns {Boolean}
   */
  public static decrypt(key: Buffer, iv: Buffer, msg: Buffer, tag: Buffer, aad: Buffer): boolean {
    const aead = new AEAD();

    aead.init(key, iv);

    if (aad)
      aead.aad(aad);

    aead.decrypt(msg);

    return aead.verify(tag);
  }

  /**
   * Authenticate data without decrypting.
   * 
   * @param {Buffer} key
   * @param {Buffer} iv
   * @param {Buffer} msg
   * @param {Buffer} tag
   * @param {Buffer?} aad
   * @returns {Boolean}
   */
  public static auth(key: Buffer, iv: Buffer, msg: Buffer, tag: Buffer, aad?: Buffer): boolean {
    const aead = new AEAD();

    aead.init(key, iv);

    if (aad)
      aead.aad(aad);

    aead.auth(msg);

    return aead.verify(tag);
  }
}

