// The approver side of an ADR-0019 action approval with a `webauthn:` passkey:
// a port of void-which-binds-go approval/approval.go, assertion.go and fetch.go
// (v0.22.0), byte layer only (no broker state).
//
// Inbox flow (P5): wake tuple → fetch nonce → fetch (a passkey proof over
// fetchPasskeyChallenge) → openFetchResponse → the person picks a number →
// passkeyChallenge → assertion → approvalAssertion(...) to the broker.
//
// Every frame is frame(p) = uint64be(len(p)) ‖ p.

import {
  allZero, b64url, b64urlDecodeStrict, bytesEqual, concat, frame, fromHex, sha256, toBytes, u64be, utf8,
} from './bytes.js';
import { VoidWhichBindsError } from './errors.js';
import { webAuthnChallenge } from './memberkey.js';
import { isValidScope } from './scope.js';

/** @typedef {import('./bytes.js').Bytes} Bytes */

/** Go `approval.DomainChallenge`: frames the approval preimage, and is its ADR-0018 domain. */
export const DOMAIN_APPROVAL_CHALLENGE = 'void-which-binds/approval/challenge/v1';
/** Go `approval.DomainAction`: frames the action digest. */
export const DOMAIN_APPROVAL_ACTION = 'void-which-binds/approval/action/v1';
/** Go `approval.DomainFetch`: frames the fetch proof preimage, and is its ADR-0018 domain. */
export const DOMAIN_APPROVAL_FETCH = 'void-which-binds/approval/fetch/v1';

/** Go `MaxApprovalTTL`, seconds. */
export const MAX_APPROVAL_TTL_SECONDS = 60 * 60;
/** Go `MatchNumberBound`: match numbers are in [0, 100). */
export const MATCH_NUMBER_BOUND = 100;
/** Go `MatchCandidateCount`. */
export const MATCH_CANDIDATE_COUNT = 3;
const ID_LEN = 16;
const NONCE_LEN = 32;
const MAX_KIND_LEN = 32;
const MAX_SUMMARY_LEN = 1024;
const MAX_PARAMS_LEN = 64 << 10;

/** Go `ApproveTuplePrefix`. */
export const APPROVE_TUPLE_PREFIX = 'void-which-binds:approve?h=';

/**
 * @typedef {object} Action Go `approval.Action`.
 * @property {string} kind [a-z][a-z0-9-]{0,31}
 * @property {string} resource an ADR-0017 scope
 * @property {string} summary 1–1024 bytes of UTF-8, no control or bidi-format character
 * @property {Uint8Array} params opaque bytes (≤ 64 KiB), possibly empty
 */

/**
 * @typedef {object} Challenge Go `approval.Challenge` (byte-layer fields).
 * @property {string} id 32 lowercase hex
 * @property {Uint8Array} nonce 32 bytes, not all zero
 * @property {string} audience the broker's origin
 * @property {number} issuedAt Unix seconds (not in the preimage)
 * @property {number} expiresAt Unix seconds
 * @property {number} matchNumber 0 on the approver's side (unknown to it)
 * @property {number[]} candidates the numbers the approver shows
 * @property {Uint8Array} actionDigest 32 bytes
 * @property {string} resource an ADR-0017 scope
 * @property {number} ttl whole seconds, 0–3600
 */

const malformed = (/** @type {string} */ why) => new VoidWhichBindsError('malformed', why);

/**
 * @param {string} k
 */
function checkKind(k) {
  if (typeof k !== 'string' || k === '' || k.length > MAX_KIND_LEN) return false;
  return /^[a-z][a-z0-9-]*$/.test(k);
}

/**
 * Go unicode.IsControl (C0, DEL, C1) or an explicit bidi formatting character.
 * @param {number} cp
 */
function forbiddenRune(cp) {
  return cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) ||
    (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) ||
    cp === 0x200e || cp === 0x200f || cp === 0x061c;
}

/**
 * @param {string} s
 * @returns {string | null} why it is refused, or null
 */
function checkSummary(s) {
  if (typeof s !== 'string') return 'not a string';
  let bytes;
  try {
    bytes = utf8(s);
  } catch {
    return 'not valid UTF-8';
  }
  if (bytes.length === 0 || bytes.length > MAX_SUMMARY_LEN) return `${bytes.length} bytes; a summary is 1 to ${MAX_SUMMARY_LEN}`;
  for (const ch of s) {
    const cp = /** @type {number} */ (ch.codePointAt(0));
    if (forbiddenRune(cp)) return `contains U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
  }
  return null;
}

/**
 * Go `Action.Check`.
 * @param {Action} a
 */
export function checkAction(a) {
  if (!checkKind(a.kind)) throw malformed(`kind ${JSON.stringify(a.kind)} is not [a-z][a-z0-9-]{0,31}`);
  if (!isValidScope(a.resource)) throw malformed(`resource ${JSON.stringify(a.resource)} is not a scope`);
  const why = checkSummary(a.summary);
  if (why) throw malformed(`summary: ${why}`);
  if (!(a.params instanceof Uint8Array)) throw malformed('params are bytes');
  if (a.params.length > MAX_PARAMS_LEN) throw malformed(`params: ${a.params.length} bytes, over ${MAX_PARAMS_LEN}`);
}

/**
 * Go `Action.Digest`:
 * SHA-256( frame(DomainAction) ‖ frame(kind) ‖ frame(resource) ‖ frame(summary) ‖ frame(params) ).
 * @param {Action} a
 * @returns {Promise<Bytes>}
 */
export async function actionDigest(a) {
  checkAction(a);
  return sha256(concat(
    frame(utf8(DOMAIN_APPROVAL_ACTION)), frame(utf8(a.kind)), frame(utf8(a.resource)),
    frame(utf8(a.summary)), frame(a.params),
  ));
}

/**
 * Go `Challenge.check` (before Preimage).
 * @param {Challenge} c
 */
function checkChallenge(c) {
  if (typeof c.id !== 'string' || c.id.length !== 2 * ID_LEN || c.id !== c.id.toLowerCase() || !fromHex(c.id)) {
    throw malformed('id is not 32 lowercase hex');
  }
  if (!(c.nonce instanceof Uint8Array) || c.nonce.length !== NONCE_LEN) throw malformed('nonce is not 32 bytes');
  if (allZero(c.nonce)) throw malformed('the nonce is all zero');
  if (typeof c.audience !== 'string' || c.audience === '') throw malformed('empty audience');
  if (!Number.isSafeInteger(c.expiresAt) || c.expiresAt <= 0) throw malformed(`expires_at ${c.expiresAt} is not after the epoch`);
  if (!Number.isInteger(c.matchNumber) || c.matchNumber < 0 || c.matchNumber >= MATCH_NUMBER_BOUND) {
    throw malformed(`match number ${c.matchNumber} is outside [0, ${MATCH_NUMBER_BOUND})`);
  }
  if (!(c.actionDigest instanceof Uint8Array) || c.actionDigest.length !== 32) throw malformed('action digest is not 32 bytes');
  if (!isValidScope(c.resource)) throw malformed(`resource ${JSON.stringify(c.resource)} is not a scope`);
  if (!Number.isInteger(c.ttl) || c.ttl < 0) throw malformed(`ttl ${c.ttl} is not a non-negative whole number of seconds`);
  if (c.ttl > MAX_APPROVAL_TTL_SECONDS) throw malformed(`ttl ${c.ttl}s exceeds ${MAX_APPROVAL_TTL_SECONDS}s`);
}

/**
 * Go `Challenge.Preimage`, the exact bytes an approver signs:
 *
 *     frame(DomainChallenge) frame(id) frame(nonce) frame(audience)
 *     frame(uint64be(expiresAt)) frame(uint64be(matchNumber)) frame(actionDigest)
 *     frame(resource) frame(uint64be(ttl))
 *
 * @param {Challenge} c
 * @returns {Bytes}
 */
export function challengePreimage(c) {
  checkChallenge(c);
  return concat(
    frame(utf8(DOMAIN_APPROVAL_CHALLENGE)), frame(utf8(c.id)), frame(c.nonce), frame(utf8(c.audience)),
    frame(u64be(c.expiresAt)), frame(u64be(c.matchNumber)), frame(c.actionDigest),
    frame(utf8(c.resource)), frame(u64be(c.ttl)),
  );
}

/**
 * Go `bound`: c with the chosen number in place of its own, after checking the
 * fetched action recomputes to c's digest and names c's resource.
 * @param {Challenge} c
 * @param {Action} fetched
 * @param {number} chosen
 */
async function bound(c, fetched, chosen) {
  const d = await actionDigest(fetched);
  if (!(c.actionDigest instanceof Uint8Array) || !bytesEqual(d, c.actionDigest)) {
    throw new VoidWhichBindsError('action_mismatch', "the action's digest is not the challenge's", { detail: 'digest_mismatch' });
  }
  if (fetched.resource !== c.resource) {
    throw new VoidWhichBindsError('action_mismatch', "the action's resource is not the challenge's", { detail: 'resource_mismatch' });
  }
  return challengePreimage({ ...c, matchNumber: chosen });
}

/**
 * Go `approval.PasskeyChallenge(c, fetched, chosen)`: the 32-byte WebAuthn
 * challenge a passkey approver asserts over, webAuthnChallenge(DomainChallenge,
 * preimage bound to the chosen number). Refuses ('action_mismatch' with
 * detail digest_mismatch / resource_mismatch, or 'malformed') unless the
 * fetched action is the one the challenge was minted for: the approver signs
 * only what it displayed.
 * @param {Challenge} c
 * @param {Action} fetched
 * @param {number} chosen the number the person tapped
 * @returns {Promise<Bytes>}
 */
export async function passkeyChallenge(c, fetched, chosen) {
  return webAuthnChallenge(DOMAIN_APPROVAL_CHALLENGE, await bound(c, fetched, chosen));
}

/**
 * Go `approval.WebAuthnAssertion` → the JSON body the broker takes
 * (Go `approval.Assertion`), in its field order:
 * { credential, ops?, roster?, sig: b64url(envelope), match_number }.
 * @param {string} credential the approver's admitting op token
 * @param {number} chosen
 * @param {ArrayBuffer | ArrayBufferView} envelope assembleEnvelope's bytes
 * @param {{ ops?: string[], roster?: string[] }} [ctx] presented person / roster ops
 * @returns {{ credential: string, ops?: string[], roster?: string[], sig: string, match_number: number }}
 */
export function approvalAssertion(credential, chosen, envelope, ctx = {}) {
  const env = toBytes(envelope);
  if (typeof credential !== 'string' || credential === '' || env.length === 0) {
    throw malformed('a credential and an envelope are required');
  }
  // Built in Go's field order, so JSON.stringify matches encoding/json's.
  const out = /** @type {{ credential: string, ops?: string[], roster?: string[], sig: string, match_number: number }} */ (
    /** @type {unknown} */ ({ credential })
  );
  if (ctx.ops && ctx.ops.length) out.ops = [...ctx.ops];
  if (ctx.roster && ctx.roster.length) out.roster = [...ctx.roster];
  out.sig = b64url(env);
  out.match_number = chosen;
  return out;
}

// --- the handle, the fetch nonce and the approve tuple --------------------------

/**
 * Go `decodeCanonical`: strict unpadded base64url that is the canonical
 * encoding of what it decodes to.
 * @param {unknown} s
 * @returns {Bytes | null}
 */
export function decodeCanonical(s) {
  if (typeof s !== 'string') return null;
  const b = b64urlDecodeStrict(s);
  return b && b64url(b) === s ? b : null;
}

/**
 * Go parse32: 43 characters, canonical, 32 bytes, not all zero.
 * @param {unknown} s
 */
function parse32(s) {
  if (typeof s !== 'string' || s.length !== 43) return null;
  const b = decodeCanonical(s);
  return b && b.length === 32 && !allZero(b) ? b : null;
}

/**
 * Go `approval.ParseHandle`. Refuses with 'unknown_handle'.
 * @param {string} s
 * @returns {Bytes}
 */
export function parseHandle(s) {
  const b = parse32(s);
  if (!b) throw new VoidWhichBindsError('unknown_handle', 'not a handle');
  return b;
}

/**
 * Go `approval.ParseFetchNonce`. Refuses with 'fetch_nonce_spent'.
 * @param {string} s
 * @returns {Bytes}
 */
export function parseFetchNonce(s) {
  const b = parse32(s);
  if (!b) throw new VoidWhichBindsError('fetch_nonce_spent', 'not a fetch nonce');
  return b;
}

/**
 * Go `approval.ParseApprove`: an exact match of "void-which-binds:approve?h="
 * and a handle's 43 characters, nothing else. Refuses with 'unknown_handle'.
 * @param {string} tuple
 * @returns {Bytes} the handle
 */
export function parseApprove(tuple) {
  if (typeof tuple !== 'string' || !tuple.startsWith(APPROVE_TUPLE_PREFIX)) {
    throw new VoidWhichBindsError('unknown_handle', 'not an approve tuple');
  }
  return parseHandle(tuple.slice(APPROVE_TUPLE_PREFIX.length));
}

/**
 * Go `approval.EncodeApprove`.
 * @param {Uint8Array} handle
 * @returns {string}
 */
export function encodeApprove(handle) {
  if (!(handle instanceof Uint8Array) || handle.length !== 32 || allZero(handle)) {
    throw new VoidWhichBindsError('unknown_handle', 'the handle is not 32 non-zero bytes');
  }
  return APPROVE_TUPLE_PREFIX + b64url(handle);
}

/**
 * Go `approval.FetchPreimage`:
 * frame(DomainFetch) frame(audience) frame(handle) frame(nonce), the handle
 * and nonce framed as their raw 32 bytes.
 * @param {string} audience the broker's origin
 * @param {Uint8Array} handle
 * @param {Uint8Array} nonce
 * @returns {Bytes}
 */
export function fetchPreimage(audience, handle, nonce) {
  if (typeof audience !== 'string' || audience === '') throw malformed('empty audience');
  if (!(handle instanceof Uint8Array) || handle.length !== 32 || allZero(handle)) throw malformed('the handle is all zero or not 32 bytes');
  if (!(nonce instanceof Uint8Array) || nonce.length !== 32 || allZero(nonce)) throw malformed('the nonce is all zero or not 32 bytes');
  return concat(frame(utf8(DOMAIN_APPROVAL_FETCH)), frame(utf8(audience)), frame(handle), frame(nonce));
}

/**
 * Go `approval.FetchPasskeyChallenge`: webAuthnChallenge(DomainFetch,
 * fetchPreimage(audience, handle, nonce)).
 * @param {string} audience
 * @param {Uint8Array} handle
 * @param {Uint8Array} nonce
 * @returns {Promise<Bytes>}
 */
export function fetchPasskeyChallenge(audience, handle, nonce) {
  return webAuthnChallenge(DOMAIN_APPROVAL_FETCH, fetchPreimage(audience, handle, nonce));
}

/**
 * The body of POST /approval/fetch (Go `approval.FetchRequest`), in its field
 * order: { handle, nonce, credential, ops?, roster?, proof: b64url(envelope) }.
 * @param {{ handle: string, nonce: string, credential: string, envelope: ArrayBuffer | ArrayBufferView, ops?: string[], roster?: string[] }} r
 */
export function fetchRequest(r) {
  /** @type {{ handle: string, nonce: string, credential: string, ops?: string[], roster?: string[], proof: string }} */
  const out = /** @type {any} */ ({ handle: r.handle, nonce: r.nonce, credential: r.credential });
  if (r.ops && r.ops.length) out.ops = [...r.ops];
  if (r.roster && r.roster.length) out.roster = [...r.roster];
  out.proof = b64url(toBytes(r.envelope));
  return out;
}

/**
 * @param {unknown} v
 * @returns {v is number}
 */
function isInt(v) {
  return typeof v === 'number' && Number.isSafeInteger(v);
}

/**
 * Go `FetchResponse.Open`: the approver's reading of a fetch answer
 * ({ challenge, action } as the broker sent it, parsed JSON). It decodes and
 * checks both and refuses ('action_mismatch') an action that does not
 * recompute to the challenge's digest or name its resource. Only then may the
 * approver display the summary and resource and sign. The returned challenge
 * has matchNumber 0 (the approver never learns it).
 * @param {any} resp
 * @returns {Promise<{ challenge: Challenge, action: Action }>}
 */
export async function openFetchResponse(resp) {
  const fc = resp && resp.challenge;
  const wa = resp && resp.action;
  if (!fc || typeof fc !== 'object' || !wa || typeof wa !== 'object') throw malformed('not a fetch response');
  for (const k of ['id', 'nonce', 'audience', 'action_digest', 'resource']) {
    if (typeof fc[k] !== 'string') throw malformed(`challenge ${k} is not a string`);
  }
  for (const k of ['issued_at', 'expires_at', 'ttl']) {
    if (!isInt(fc[k])) throw malformed(`challenge ${k} is not an integer`);
  }
  const nonce = decodeCanonical(fc.nonce);
  if (!nonce || nonce.length !== NONCE_LEN) throw malformed('challenge nonce');
  const digest = decodeCanonical(fc.action_digest);
  if (!digest || digest.length !== 32) throw malformed('action digest');
  const cs = fc.candidates;
  if (!Array.isArray(cs) || cs.length !== MATCH_CANDIDATE_COUNT ||
      !cs.every((n) => isInt(n) && n >= 0 && n < MATCH_NUMBER_BOUND) || new Set(cs).size !== cs.length) {
    throw malformed('candidates');
  }
  if (fc.ttl < 0 || fc.ttl > MAX_APPROVAL_TTL_SECONDS) throw malformed(`ttl ${fc.ttl}s`);
  /** @type {Challenge} */
  const c = {
    id: fc.id, nonce, audience: fc.audience, issuedAt: fc.issued_at, expiresAt: fc.expires_at,
    matchNumber: 0, candidates: [...cs], actionDigest: digest, resource: fc.resource, ttl: fc.ttl,
  };
  challengePreimage(c);
  for (const k of ['kind', 'resource', 'summary', 'params']) {
    if (typeof wa[k] !== 'string') throw malformed(`action ${k} is not a string`);
  }
  const params = decodeCanonical(wa.params);
  if (!params) throw malformed('action params');
  /** @type {Action} */
  const a = { kind: wa.kind, resource: wa.resource, summary: wa.summary, params };
  const d = await actionDigest(a);
  if (!bytesEqual(d, c.actionDigest)) {
    throw new VoidWhichBindsError('action_mismatch', "the action's digest is not the challenge's", { detail: 'digest_mismatch' });
  }
  if (a.resource !== c.resource) {
    throw new VoidWhichBindsError('action_mismatch', "the action's resource is not the challenge's", { detail: 'resource_mismatch' });
  }
  return { challenge: c, action: a };
}
