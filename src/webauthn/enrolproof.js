// The ADR-0018 enrolment proof of possession (amended 2026-10-04, "Enrolment
// proof"): a port of void-which-binds-go roster/enrolproof.go (v0.24.0),
// byte layer only. The broker owns single use (one live nonce per invite,
// consumed with the invite); none of that state lives here.
//
// A candidate member key proves possession of itself to the broker once,
// before the broker drafts the `enrol` that admits it:
//
//     B = frame(DomainEnrolProof) ‖ frame(aud) ‖ frame(org) ‖ frame(mem) ‖
//         frame(key) ‖ frame(nonce) ‖ frame(u64be(iat)) ‖ frame(u64be(exp))
//
// with frame(p) = uint64be(len(p)) ‖ p (ADR-0019's framing). A `webauthn:`
// candidate asserts over webAuthnChallenge(DomainEnrolProof, B); an `ed25519:`
// candidate signs B directly.

import { allZero, concat, frame, u64be, utf8 } from './bytes.js';
import { VoidWhichBindsError } from './errors.js';
import { isCanonicalEd25519, KIND_WEBAUTHN, parseMemberKey, verifyMemberSignature, webAuthnChallenge } from './memberkey.js';

/** @typedef {import('./bytes.js').Bytes} Bytes */
/** @typedef {import('./memberkey.js').WebAuthnPolicy} WebAuthnPolicy */

/** Go `roster.DomainEnrolProof`: the preimage's first frame, and its ADR-0018 domain. */
export const DOMAIN_ENROL_PROOF = 'void-which-binds/roster/enrol-proof/v1';
/** Go `roster.EnrolProofNonceLen`. */
export const ENROL_PROOF_NONCE_LEN = 32;
/** Go `roster.EnrolProofMaxTTL`, seconds: 0 < exp − iat ≤ 120. */
export const ENROL_PROOF_MAX_TTL_SECONDS = 120;
/** Go `roster.ManagedPrefix`. */
export const MANAGED_PREFIX = 'mp:';

/**
 * @typedef {object} EnrolProof Go `roster.EnrolProof`. On the broker every
 *   field comes from its own invite and nonce records; on the client they come
 *   from the invite and the nonce the broker issued against this key.
 * @property {string} audience the broker's origin, e.g. "https://moneta.example"
 * @property {string} org the org id, canonical "ed25519:<64 hex>"
 * @property {string} mem the managed person, "mp:<32 lowercase hex>"
 * @property {string} key the candidate member key, "webauthn:es256:<130 hex>"
 *   or "ed25519:<64 hex>", canonical
 * @property {Uint8Array} nonce the broker's 32 bytes, not all zero
 * @property {number | Date} issuedAt whole Unix seconds (or a Date on a whole second)
 * @property {number | Date} expiresAt whole Unix seconds (or a Date on a whole second)
 */

const malformed = (/** @type {string} */ why) => new VoidWhichBindsError('malformed', why);

/**
 * Whole Unix seconds, or null when t has a sub-second part (Go's
 * `Nanosecond() != 0`) or is not a time.
 * @param {unknown} t
 * @returns {number | null}
 */
function wholeSeconds(t) {
  if (t instanceof Date) {
    const ms = t.getTime();
    return Number.isSafeInteger(ms) && ms % 1000 === 0 ? ms / 1000 : null;
  }
  return typeof t === 'number' && Number.isSafeInteger(t) ? t : null;
}

/**
 * Go `validManagedID`: "mp:" and 32 lowercase hex.
 * @param {unknown} s
 * @returns {boolean}
 */
export function isManagedId(s) {
  return typeof s === 'string' && /^mp:[0-9a-f]{32}$/.test(s);
}

/**
 * Go `validMemberKey`: a canonical ed25519 key, or a webauthn:es256 key whose
 * point is on P-256.
 * @param {unknown} s
 * @returns {boolean}
 */
export function isEnrollableKey(s) {
  if (isCanonicalEd25519(/** @type {string} */ (s))) return true;
  try {
    return parseMemberKey(/** @type {string} */ (s)).kind === KIND_WEBAUTHN;
  } catch {
    return false;
  }
}

/**
 * Go `EnrolProof.check`, in its order. Refuses with 'malformed'.
 * @param {EnrolProof} p
 * @returns {{ iat: number, exp: number }}
 */
export function checkEnrolProof(p) {
  if (!p || typeof p !== 'object') throw malformed('an enrol proof is required');
  if (typeof p.audience !== 'string' || p.audience === '') throw malformed('empty audience');
  if (!isCanonicalEd25519(p.org)) throw malformed(`org ${JSON.stringify(p.org)} is not a canonical ed25519 key`);
  if (!isManagedId(p.mem)) throw malformed(`mem ${JSON.stringify(p.mem)} is not an "${MANAGED_PREFIX}" id`);
  if (!isEnrollableKey(p.key)) throw malformed(`key ${JSON.stringify(p.key)} may not be enrolled`);
  if (!(p.nonce instanceof Uint8Array) || p.nonce.length !== ENROL_PROOF_NONCE_LEN) {
    throw malformed(`the nonce is ${ENROL_PROOF_NONCE_LEN} bytes`);
  }
  if (allZero(p.nonce)) throw malformed('the nonce is all zero');
  const iat = wholeSeconds(p.issuedAt);
  const exp = wholeSeconds(p.expiresAt);
  // The preimage signs whole Unix seconds; a sub-second part would make the
  // window checked differ from the window signed.
  if (iat === null || exp === null) throw malformed('issued_at and expires_at must be whole seconds');
  if (iat <= 0) throw malformed(`issued_at ${iat} is not after the epoch`);
  if (exp <= iat) throw malformed('expires_at is not after issued_at');
  if (exp - iat > ENROL_PROOF_MAX_TTL_SECONDS) throw malformed(`the window exceeds ${ENROL_PROOF_MAX_TTL_SECONDS}s`);
  return { iat, exp };
}

/**
 * Go `EnrolProof.Preimage`: the exact bytes an enrol proof signs (see the file
 * header). Every field is framed, the nonce as its raw 32 bytes and iat/exp as
 * 8-byte big-endian Unix seconds. Refuses with 'malformed'.
 * @param {EnrolProof} p
 * @returns {Bytes}
 */
export function enrolProofPreimage(p) {
  const { iat, exp } = checkEnrolProof(p);
  return concat(
    frame(utf8(DOMAIN_ENROL_PROOF)), frame(utf8(p.audience)), frame(utf8(p.org)), frame(utf8(p.mem)),
    frame(utf8(p.key)), frame(p.nonce), frame(u64be(iat)), frame(u64be(exp)),
  );
}

/**
 * Go `EnrolProof.PasskeyChallenge`: webAuthnChallenge(DomainEnrolProof,
 * preimage), the 32 bytes a `webauthn:` candidate asserts over with
 * userVerification "required".
 * @param {EnrolProof} p
 * @returns {Promise<Bytes>}
 */
export async function enrolProofChallenge(p) {
  return webAuthnChallenge(DOMAIN_ENROL_PROOF, enrolProofPreimage(p));
}

/**
 * Go `VerifyEnrolProof` + `EnrolProofReason`: 'malformed' (the fields),
 * 'expired' (now outside [iat, exp)), then MemberKey.VerifyBody under p.key
 * with ADR-0018's word ('ok', 'challenge_mismatch', 'wrong_ceremony',
 * 'user_not_verified', 'synced_not_allowed', 'bad_signature', …).
 *
 * The broker is the authority (it rebuilds p from its own records and owns
 * single use); this is the client's pre-flight and the vector replay.
 *
 * @param {EnrolProof} p
 * @param {Uint8Array} sig an `ed25519:` key's raw 64 bytes, or a `webauthn:`
 *   key's ADR-0018 envelope bytes
 * @param {WebAuthnPolicy} policy
 * @param {number | Date} now Unix seconds (or a Date)
 * @returns {Promise<string>}
 */
export async function verifyEnrolProof(p, sig, policy, now) {
  let pre;
  try {
    pre = enrolProofPreimage(p);
  } catch (e) {
    if (e instanceof VoidWhichBindsError) return 'malformed';
    throw e;
  }
  const t = now instanceof Date ? now.getTime() / 1000 : now;
  if (typeof t !== 'number' || Number.isNaN(t)) throw new TypeError('now is Unix seconds or a Date');
  const iat = /** @type {number} */ (wholeSeconds(p.issuedAt));
  const exp = /** @type {number} */ (wholeSeconds(p.expiresAt));
  if (t < iat || !(t < exp)) return 'expired';
  return verifyMemberSignature(p.key, DOMAIN_ENROL_PROOF, pre, sig, policy);
}
