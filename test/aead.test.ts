'use strict';

import {assert} from "bsert";
import {AEAD} from "../src";
import vectors from "./data/aead.json";

describe('AEAD (ChaCha20+Poly1305)', function() {
  for (const [plain_, aad_, key_, nonce_, raw_] of vectors) {
    const input = Buffer.from(plain_, 'hex');
    const aad = Buffer.from(aad_, 'hex');
    const key = Buffer.from(key_, 'hex');
    const nonce = Buffer.from(nonce_, 'hex');
    const raw = Buffer.from(raw_, 'hex');
    const output = raw.slice(0, -16);
    const tag = raw.slice(-16);
    const text = key_.slice(0, 32) + '...';

    it(`should do incremental encrypt and decrypt (${text})`, () => {
      const data = Buffer.from(input);
      const ctx = new AEAD();

      ctx.init(key, nonce);
      ctx.aad(aad);
      ctx.encrypt(data);

      assert.bufferEqual(data, output);
      assert.bufferEqual(ctx.final(), tag);

      ctx.init(key, nonce);
      ctx.aad(aad);
      ctx.auth(data);

      assert.bufferEqual(ctx.final(), tag);

      ctx.init(key, nonce);
      ctx.aad(aad);
      ctx.decrypt(data);

      assert.bufferEqual(data, input);
      assert.bufferEqual(ctx.final(), tag);

      ctx.destroy();
    });

    it(`should do incremental encrypt and decrypt + verify (${text})`, () => {
      const data = Buffer.from(input);
      const ctx = new AEAD();

      ctx.init(key, nonce);
      ctx.aad(aad);
      ctx.encrypt(data);

      assert.bufferEqual(data, output);
      assert.strictEqual(ctx.verify(tag), true);

      ctx.init(key, nonce);
      ctx.aad(aad);
      ctx.auth(data);

      assert.strictEqual(ctx.verify(tag), true);

      ctx.init(key, nonce);
      ctx.aad(aad);
      ctx.decrypt(data);

      assert.bufferEqual(data, input);
      assert.strictEqual(ctx.verify(tag), true);

      ctx.init(key, nonce);
      ctx.aad(aad);
      ctx.encrypt(data);

      const tag0 = Buffer.from(tag);

      tag0[0] ^= 1;

      assert.bufferEqual(data, output);
      assert.strictEqual(ctx.verify(tag0), false);
    });

    it(`should do one-shot encrypt and decrypt (${text})`, () => {
      const data = Buffer.from(input);
      const mac = AEAD.encrypt(key, nonce, data, aad);

      assert.bufferEqual(data, output);
      assert.bufferEqual(mac, tag);

      assert(AEAD.auth(key, nonce, data, tag, aad));
      assert(AEAD.decrypt(key, nonce, data, tag, aad));

      assert.bufferEqual(data, input);

      assert.bufferEqual(AEAD.encrypt(key, nonce, data, aad), tag);

      key[0] ^= 1;

      assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, key));

      key[0] ^= 1;

      assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

      nonce[0] ^= 1;

      assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, key));

      nonce[0] ^= 1;

      assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

      tag[0] ^= 1;

      assert(!AEAD.auth(key, nonce, data, tag, aad));
      assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, key));

      tag[0] ^= 1;

      assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

      if (data.length > 0) {
        data[0] ^= 1;

        assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

        data[0] ^= 1;

        assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));
      }

      if (aad.length > 0) {
        aad[0] ^= 1;

        assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

        aad[0] ^= 1;

        assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));
      }
    });

    it(`should do one-shot encrypt and decrypt without changing original message (${text})`, () => {
      const data = Buffer.from(input);
      const original_data = data
      const result = AEAD.safeEncrypt(key, nonce, data, aad);

      assert.bufferEqual(result['cipher'], output);
      assert.bufferEqual(result['mac'], tag);
      assert.bufferEqual(data, original_data)

      assert(AEAD.auth(key, nonce, result['cipher'], tag, aad));

      const original_cipher = result['cipher']
      const decryptedMessage = AEAD.safeDecrypt(key, nonce, result['cipher'], tag, aad);
      assert.bufferEqual(decryptedMessage, input);
      assert.bufferEqual(result['cipher'], original_cipher)

      key[0] ^= 1;
      assert.throws(
        () => {AEAD.safeDecrypt(key, nonce, Buffer.from(data), tag, key)},
        Error,
        'Cipher could not be decrypted'
      );
    });
  }
});