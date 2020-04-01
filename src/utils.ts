
/*!
 * assert.js - assert for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

export function assert(val: any, msg?: string) {
  if (!val) {
    const err = new Error(msg || 'Assertion failed');

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assert);

    throw err;
  }
}

export function readU16(data, off) {
  return data[off++] + data[off] * 0x100;
}

export function writeU16(dst, num, off) {
  dst[off++] = num;
  dst[off++] = num >>> 8;
  return off;
}

export function writeU32(dst, num, off) {
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  return off;
}

export function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

export function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}


export function writeU64(dst, num, off) {
  const hi = (num * (1 / 0x100000000)) >>> 0;
  const lo = num >>> 0;

  writeU32(dst, lo, off + 0);
  writeU32(dst, hi, off + 4);

  return off + 8;
}

export function qround(x, a, b, c, d) {
  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 16);

  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 12);

  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 8);

  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 7);
}
