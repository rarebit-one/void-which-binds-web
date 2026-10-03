// Byte helpers shared by the WebAuthn signer: hex, unpadded base64url with Go's
// exact strictness, UTF-8, SHA-256 (WebCrypto) and the ADR-0019 length frame.
//
// Nothing here is a protocol decision; each helper mirrors the Go standard
// library call void-which-binds-go makes, so the byte layer cannot drift.

import { VoidWhichBindsError } from './errors.js';

/** @typedef {Uint8Array<ArrayBuffer>} Bytes */

const HEX = '0123456789abcdef';

/**
 * Lowercase hex, as Go's encoding/hex.EncodeToString.
 * @param {Uint8Array} b
 * @returns {string}
 */
export function toHex(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) s += HEX[b[i] >> 4] + HEX[b[i] & 15];
  return s;
}

/**
 * Decodes hex of either case (Go's hex.DecodeString). Callers that require one
 * spelling check the case themselves, as Go's callers do.
 * @param {string} s
 * @returns {Bytes | null} null when s is not hex
 */
export function fromHex(s) {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_INDEX = new Int16Array(128).fill(-1);
for (let i = 0; i < B64URL.length; i++) B64URL_INDEX[B64URL.charCodeAt(i)] = i;

/**
 * Unpadded base64url (Go's base64.RawURLEncoding.EncodeToString).
 * @param {Uint8Array} b
 * @returns {string}
 */
export function b64url(b) {
  let s = '';
  let i = 0;
  for (; i + 3 <= b.length; i += 3) {
    const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    s += B64URL[n >> 18] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63] + B64URL[n & 63];
  }
  const rem = b.length - i;
  if (rem === 1) {
    const n = b[i] << 16;
    s += B64URL[n >> 18] + B64URL[(n >> 12) & 63];
  } else if (rem === 2) {
    const n = (b[i] << 16) | (b[i + 1] << 8);
    s += B64URL[n >> 18] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63];
  }
  return s;
}

/**
 * Strict unpadded base64url, as Go's base64.RawURLEncoding.Strict(): no
 * padding, no character outside the URL alphabet, and no non-zero trailing
 * bits, so every value has exactly one spelling.
 *
 * Go's decoder silently skips '\r' and '\n' even in Strict mode. Pass
 * `skipNewlines: true` only where the Go caller relies on that (a delegation's
 * jti/non claim); every WebAuthn and approval caller refuses them, as Go does.
 *
 * @param {string} s
 * @param {{ skipNewlines?: boolean }} [opts]
 * @returns {Bytes | null} null when s is not strict unpadded base64url
 */
export function b64urlDecodeStrict(s, opts = {}) {
  if (typeof s !== 'string') return null;
  const src = opts.skipNewlines ? s.replace(/[\r\n]/g, '') : s;
  const rem = src.length % 4;
  if (rem === 1) return null;
  const out = new Uint8Array(Math.floor((src.length * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src.charCodeAt(i);
    const v = c < 128 ? B64URL_INDEX[c] : -1;
    if (v < 0) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  // Strict: the bits left over after the last whole byte must be zero.
  if (acc !== 0) return null;
  return out.subarray(0, o);
}

const utf8Encoder = new TextEncoder();
const utf8Fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const utf8Lossy = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });

/**
 * A JS string's UTF-8 bytes. A lone surrogate has no UTF-8 encoding, and Go
 * would carry U+FFFD in its place, so it is refused (malformed) rather than
 * silently replaced.
 * @param {string} s
 * @returns {Bytes}
 */
export function utf8(s) {
  if (!isWellFormed(s)) throw new VoidWhichBindsError('malformed', 'string contains a lone surrogate');
  return /** @type {Bytes} */ (utf8Encoder.encode(s));
}

/**
 * @param {string} s
 * @returns {boolean} whether s has no lone surrogate (String#isWellFormed)
 */
export function isWellFormed(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Go's utf8.Valid.
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function validUtf8(b) {
  try {
    utf8Fatal.decode(b);
    return true;
  } catch {
    return false;
  }
}

/**
 * Decodes UTF-8, replacing invalid sequences with U+FFFD as Go's
 * encoding/json does when it decodes a string.
 * @param {Uint8Array} b
 * @returns {string}
 */
export function decodeUtf8Lossy(b) {
  return utf8Lossy.decode(b);
}

/**
 * @param {...Uint8Array} parts
 * @returns {Bytes}
 */
export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function allZero(b) {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false;
  return true;
}

/**
 * uint64 big-endian of a non-negative safe integer (Go binary.BigEndian.AppendUint64).
 * @param {number} n
 * @returns {Bytes}
 */
export function u64be(n) {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new VoidWhichBindsError('malformed', `${n} is not a non-negative safe integer`);
  }
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * ADR-0019's frame(p) = uint64be(len(p)) ‖ p.
 * @param {Uint8Array} p
 * @returns {Bytes}
 */
export function frame(p) {
  return concat(u64be(p.length), p);
}

/**
 * The ambient WebCrypto SubtleCrypto (browsers, Node >= 19).
 * @returns {SubtleCrypto}
 */
export function subtle() {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) throw new Error('void-which-binds-web: WebCrypto (crypto.subtle) is not available');
  return s;
}

/**
 * SHA-256 through WebCrypto.
 * @param {Uint8Array} b
 * @returns {Promise<Bytes>}
 */
export async function sha256(b) {
  return new Uint8Array(await subtle().digest('SHA-256', /** @type {Bytes} */ (b)));
}

/**
 * Accepts a BufferSource (or Uint8Array) and returns a Uint8Array view copy.
 * @param {ArrayBuffer | ArrayBufferView} src
 * @returns {Bytes}
 */
export function toBytes(src) {
  if (src instanceof Uint8Array) return /** @type {Bytes} */ (new Uint8Array(src));
  if (ArrayBuffer.isView(src)) {
    const out = new Uint8Array(src.byteLength);
    out.set(new Uint8Array(src.buffer, src.byteOffset, src.byteLength));
    return out;
  }
  if (src instanceof ArrayBuffer) return new Uint8Array(src.slice(0));
  throw new TypeError('expected an ArrayBuffer or a typed array');
}
