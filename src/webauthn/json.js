// JSON exactly as void-which-binds-go speaks it.
//
// - goJsonString / goJsonMarshal: Go's encoding/json output (Go >= 1.22), which
//   is what a canonical body is. It differs from JSON.stringify: '<', '>' and
//   '&' are escaped as < > & (HTML escaping), as are U+2028 and
//   U+2029, and \b and \f use their short escapes. A delegation whose aud
//   carries '&' is only canonical in Go's spelling (vector aud-with-ampersand).
// - parseJson: an RFC 8259 parser over BYTES that can refuse duplicate keys at
//   any depth and bound nesting, mirroring identity/webauthn.go's strictObject
//   and walkJSON. JSON.parse cannot do either (it keeps the last duplicate).

import { b64url, decodeUtf8Lossy, isWellFormed } from './bytes.js';
import { VoidWhichBindsError } from './errors.js';

const HEX = '0123456789abcdef';

/**
 * A string as Go's json.Marshal renders it (HTML escaping on).
 * @param {string} s
 * @returns {string}
 */
export function goJsonString(s) {
  if (!isWellFormed(s)) throw new VoidWhichBindsError('malformed', 'string contains a lone surrogate');
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else if (c < 0x20 || c === 0x3c || c === 0x3e || c === 0x26) out += '\\u00' + HEX[c >> 4] + HEX[c & 15];
    else if (c === 0x2028) out += '\\u2028';
    else if (c === 0x2029) out += '\\u2029';
    else out += s[i];
  }
  return out + '"';
}

/**
 * Go's json.Marshal for the value shapes canonical bodies use: strings, safe
 * integers, booleans, null, arrays, and plain objects whose key insertion
 * order is the Go struct's field order. Byte arrays are not accepted (Go would
 * render []byte as padded std base64; no canonical body here has one).
 * @param {unknown} v
 * @returns {string}
 */
export function goJsonMarshal(v) {
  if (v === null) return 'null';
  if (typeof v === 'string') return goJsonString(v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new VoidWhichBindsError('malformed', `${v} is not a safe integer`);
    return String(v);
  }
  if (Array.isArray(v)) return '[' + v.map(goJsonMarshal).join(',') + ']';
  if (typeof v === 'object') {
    return '{' + Object.entries(/** @type {Record<string, unknown>} */ (v))
      .filter(([, x]) => x !== undefined)
      .map(([k, x]) => goJsonString(k) + ':' + goJsonMarshal(x))
      .join(',') + '}';
  }
  throw new VoidWhichBindsError('malformed', `cannot encode a ${typeof v}`);
}

/**
 * @typedef {{ t: 'obj', members: Map<string, JsonNode> }
 *   | { t: 'arr', items: JsonNode[] }
 *   | { t: 'str', v: string }
 *   | { t: 'num', raw: string }
 *   | { t: 'bool', v: boolean }
 *   | { t: 'null' }} JsonNode
 */

class JsonSyntaxError extends Error {}
class JsonStrictError extends Error {}

/**
 * Parses exactly one JSON value from bytes, with optional whitespace around it.
 * Strings are decoded as Go decodes them: invalid UTF-8 and lone-surrogate
 * escapes become U+FFFD.
 *
 * @param {Uint8Array} bytes
 * @param {{ maxDepth?: number, rejectDuplicates?: boolean }} [opts]
 *   maxDepth counts like Go's walkJSON: the top value is depth 0, and a value
 *   nested deeper than maxDepth is refused.
 * @returns {{ ok: true, value: JsonNode } | { ok: false, syntax: boolean, why: string }}
 *   syntax is true when the bytes are not JSON at all, false when they are JSON
 *   that breaks a strict rule (a duplicate key, too deep).
 */
export function parseJson(bytes, opts = {}) {
  const maxDepth = opts.maxDepth ?? 10000;
  const rejectDuplicates = opts.rejectDuplicates ?? false;
  let i = 0;
  // Strict-rule breaks are only reported once the whole input is known to be
  // JSON, so "not JSON" always wins over "duplicate key", as Go's json.Valid
  // runs before its strict walk.
  /** @type {string | null} */
  let strictWhy = null;

  const ws = () => {
    while (i < bytes.length) {
      const c = bytes[i];
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  /** @param {string} why @returns {never} */
  const syntax = (why) => {
    throw new JsonSyntaxError(why);
  };

  const parseString = () => {
    // bytes[i] === '"'
    i++;
    /** @type {number[]} */
    const buf = [];
    for (;;) {
      if (i >= bytes.length) syntax('unterminated string');
      const c = bytes[i];
      if (c === 0x22) {
        i++;
        break;
      }
      if (c < 0x20) syntax('control character in string');
      if (c !== 0x5c) {
        buf.push(c);
        i++;
        continue;
      }
      i++;
      const e = bytes[i];
      i++;
      switch (e) {
        case 0x22: buf.push(0x22); break;
        case 0x5c: buf.push(0x5c); break;
        case 0x2f: buf.push(0x2f); break;
        case 0x62: buf.push(0x08); break;
        case 0x66: buf.push(0x0c); break;
        case 0x6e: buf.push(0x0a); break;
        case 0x72: buf.push(0x0d); break;
        case 0x74: buf.push(0x09); break;
        case 0x75: {
          let cp = readHex4();
          if (cp >= 0xd800 && cp <= 0xdbff) {
            // A high surrogate pairs only with an immediately following \uDC00–\uDFFF.
            if (bytes[i] === 0x5c && bytes[i + 1] === 0x75) {
              const save = i;
              i += 2;
              const lo = readHex4();
              if (lo >= 0xdc00 && lo <= 0xdfff) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
              } else {
                i = save;
                cp = 0xfffd;
              }
            } else {
              cp = 0xfffd;
            }
          } else if (cp >= 0xdc00 && cp <= 0xdfff) {
            cp = 0xfffd;
          }
          pushUtf8(buf, cp);
          break;
        }
        default:
          syntax('bad escape');
      }
    }
    return decodeUtf8Lossy(Uint8Array.from(buf));
  };

  const readHex4 = () => {
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const c = bytes[i++];
      let d;
      if (c >= 0x30 && c <= 0x39) d = c - 0x30;
      else if (c >= 0x41 && c <= 0x46) d = c - 0x37;
      else if (c >= 0x61 && c <= 0x66) d = c - 0x57;
      else syntax('bad \\u escape');
      v = (v << 4) | /** @type {number} */ (d);
    }
    return v;
  };

  const parseNumber = () => {
    const start = i;
    if (bytes[i] === 0x2d) i++;
    if (bytes[i] === 0x30) i++;
    else if (bytes[i] >= 0x31 && bytes[i] <= 0x39) while (bytes[i] >= 0x30 && bytes[i] <= 0x39) i++;
    else syntax('bad number');
    if (bytes[i] === 0x2e) {
      i++;
      if (!(bytes[i] >= 0x30 && bytes[i] <= 0x39)) syntax('bad fraction');
      while (bytes[i] >= 0x30 && bytes[i] <= 0x39) i++;
    }
    if (bytes[i] === 0x65 || bytes[i] === 0x45) {
      i++;
      if (bytes[i] === 0x2b || bytes[i] === 0x2d) i++;
      if (!(bytes[i] >= 0x30 && bytes[i] <= 0x39)) syntax('bad exponent');
      while (bytes[i] >= 0x30 && bytes[i] <= 0x39) i++;
    }
    return String.fromCharCode(...bytes.subarray(start, i));
  };

  /** @param {string} word */
  const literal = (word) => {
    for (let k = 0; k < word.length; k++) {
      if (bytes[i + k] !== word.charCodeAt(k)) syntax('bad literal');
    }
    i += word.length;
  };

  /**
   * @param {number} depth
   * @returns {JsonNode}
   */
  const value = (depth) => {
    if (depth > maxDepth && strictWhy === null) strictWhy = 'nested too deeply';
    ws();
    const c = bytes[i];
    if (c === 0x7b) {
      i++;
      /** @type {Map<string, JsonNode>} */
      const members = new Map();
      ws();
      if (bytes[i] === 0x7d) {
        i++;
        return { t: 'obj', members };
      }
      for (;;) {
        ws();
        if (bytes[i] !== 0x22) syntax('object key is not a string');
        const key = parseString();
        ws();
        if (bytes[i] !== 0x3a) syntax("expected ':'");
        i++;
        const v = value(depth + 1);
        if (members.has(key) && rejectDuplicates && strictWhy === null) strictWhy = `duplicate key ${JSON.stringify(key)}`;
        members.set(key, v);
        ws();
        if (bytes[i] === 0x2c) {
          i++;
          continue;
        }
        if (bytes[i] === 0x7d) {
          i++;
          return { t: 'obj', members };
        }
        syntax("expected ',' or '}'");
      }
    }
    if (c === 0x5b) {
      i++;
      /** @type {JsonNode[]} */
      const items = [];
      ws();
      if (bytes[i] === 0x5d) {
        i++;
        return { t: 'arr', items };
      }
      for (;;) {
        items.push(value(depth + 1));
        ws();
        if (bytes[i] === 0x2c) {
          i++;
          continue;
        }
        if (bytes[i] === 0x5d) {
          i++;
          return { t: 'arr', items };
        }
        syntax("expected ',' or ']'");
      }
    }
    if (c === 0x22) return { t: 'str', v: parseString() };
    if (c === 0x74) {
      literal('true');
      return { t: 'bool', v: true };
    }
    if (c === 0x66) {
      literal('false');
      return { t: 'bool', v: false };
    }
    if (c === 0x6e) {
      literal('null');
      return { t: 'null' };
    }
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return { t: 'num', raw: parseNumber() };
    return syntax('unexpected byte');
  };

  try {
    const v = value(0);
    ws();
    if (i !== bytes.length) syntax('trailing data after the value');
    if (strictWhy !== null) throw new JsonStrictError(strictWhy);
    return { ok: true, value: v };
  } catch (e) {
    if (e instanceof JsonSyntaxError) return { ok: false, syntax: true, why: e.message };
    if (e instanceof JsonStrictError) return { ok: false, syntax: false, why: e.message };
    if (e instanceof RangeError) return { ok: false, syntax: true, why: 'nested too deeply to parse' };
    throw e;
  }
}

/**
 * @param {number[]} buf
 * @param {number} cp
 */
function pushUtf8(buf, cp) {
  if (cp < 0x80) buf.push(cp);
  else if (cp < 0x800) buf.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
  else if (cp < 0x10000) buf.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  else buf.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
}

/**
 * Go's strictObject: exactly one JSON object, no duplicate key at any depth,
 * nesting at most 16 deep, no trailing data. Returns its top-level members.
 * @param {Uint8Array} bytes
 * @returns {{ ok: true, members: Map<string, JsonNode> } | { ok: false, syntax: boolean, why: string }}
 */
export function strictObject(bytes) {
  const r = parseJson(bytes, { maxDepth: 16, rejectDuplicates: true });
  if (!r.ok) return r;
  if (r.value.t !== 'obj') return { ok: false, syntax: false, why: 'not a JSON object' };
  return { ok: true, members: r.value.members };
}

/**
 * The ADR-0018 assertion envelope's bytes, exactly as void-which-binds-go
 * renders it: {"ad":<b64url>,"cd":<b64url>,"sig":<b64url>} in that member
 * order, no whitespace. base64url needs no JSON escaping.
 * @param {Uint8Array} authenticatorData
 * @param {Uint8Array} clientDataJSON
 * @param {Uint8Array} signature
 * @returns {string}
 */
export function envelopeJson(authenticatorData, clientDataJSON, signature) {
  return `{"ad":"${b64url(authenticatorData)}","cd":"${b64url(clientDataJSON)}","sig":"${b64url(signature)}"}`;
}
