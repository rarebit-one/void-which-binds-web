// The ADR-0017/0019 scope grammar: a port of void-which-binds-go scope/scope.go.
//
//   ns    [a-z][a-z0-9-]{0,31}        1–32 bytes
//   path  [a-z0-9][a-z0-9._/-]{0,127}  1–128 bytes
//
// ASCII only, compared byte for byte, nothing normalised. A list is canonical
// when it is sorted by byte order, de-duplicated and holds 1–32 entries.

import { VoidWhichBindsError } from './errors.js';

export const MAX_SCOPES = 32;

const SCOPE_RE = /^[a-z][a-z0-9-]{0,31}:[a-z0-9][a-z0-9._/-]{0,127}$/;

/**
 * Go `scope.Validate`.
 * @param {string} s
 * @returns {boolean}
 */
export function isValidScope(s) {
  return typeof s === 'string' && SCOPE_RE.test(s);
}

/**
 * Byte-order comparison. Scopes are ASCII, so UTF-16 code-unit order is byte
 * order, but a non-scope string is compared the same way Go's sort would.
 * @param {string} a
 * @param {string} b
 */
function byteCompare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Go `scope.CanonicalList`, the minter's rule: every entry valid, then sorted
 * and de-duplicated, 1–32 entries. It never mutates its input.
 * @param {string[]} scopes
 * @returns {string[]}
 * @throws {VoidWhichBindsError} reason 'malformed'
 */
export function canonicalScopeList(scopes) {
  if (!Array.isArray(scopes)) throw new VoidWhichBindsError('malformed', 'a scope list is an array');
  const seen = new Set();
  /** @type {string[]} */
  const out = [];
  for (const s of scopes) {
    if (!isValidScope(s)) throw new VoidWhichBindsError('malformed', `scope ${JSON.stringify(s)} is outside the grammar`);
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  if (out.length === 0 || out.length > MAX_SCOPES) {
    throw new VoidWhichBindsError('malformed', `a scope list holds 1 to ${MAX_SCOPES} scopes, not ${out.length}`);
  }
  return out.sort(byteCompare);
}

/**
 * Go `scope.ValidateList`, the verifier's rule: already canonical (strictly
 * ascending, 1–32 valid entries); it refuses rather than repairs.
 * @param {unknown} scopes
 * @returns {boolean}
 */
export function isCanonicalScopeList(scopes) {
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > MAX_SCOPES) return false;
  for (let i = 0; i < scopes.length; i++) {
    if (!isValidScope(scopes[i])) return false;
    if (i > 0 && byteCompare(scopes[i - 1], scopes[i]) >= 0) return false;
  }
  return true;
}
