// The issuer side of a `webauthn:` (passkey) delegation (ADR-0017/0018): a
// port of void-which-binds-go delegation/delegation.go's Body, Challenge and
// AssembleWebAuthn (v0.22.0).
//
//   const body = delegationBody(claims);            // Delegation.Body
//   const challenge = await delegationChallenge(body);   // Challenge(body)
//   ... navigator.credentials.get({ publicKey: { challenge, userVerification: 'required', … } })
//   const token = assembleDelegationWebAuthn(body, assembleEnvelope(response));
//
// The body is the exact encoding/json encoding of the payload, fields in the
// order v, typ, usr, org, iss, prn, aud, scp, jti, non, iat, exp, with Go's
// HTML escaping. A broker refuses any other encoding of the same claims.

import { b64url, b64urlDecodeStrict, bytesEqual, decodeUtf8Lossy, toBytes, utf8 } from './bytes.js';
import { VoidWhichBindsError } from './errors.js';
import { goJsonMarshal } from './json.js';
import { isCanonicalEd25519, KIND_WEBAUTHN, parseMemberKey, webAuthnChallenge } from './memberkey.js';
import { canonicalScopeList, isCanonicalScopeList } from './scope.js';

/** @typedef {import('./bytes.js').Bytes} Bytes */

/** A delegation's `v` (Go `delegation.Version`). */
export const DELEGATION_VERSION = 1;
/** A delegation's `typ` (Go `delegation.Typ`). */
export const DELEGATION_TYP = 'void-which-binds.delegation';
/** The ADR-0018 domain a passkey asserts a delegation body under (Go `delegation.Domain`). */
export const DELEGATION_DOMAIN = DELEGATION_TYP;
/** exp − iat bound, seconds (Go `delegation.MaxTTL` = grant.MaxTTL, 24h). */
export const DELEGATION_MAX_TTL_SECONDS = 24 * 60 * 60;
/** Random bytes behind `jti` (Go `JTILen`). */
export const JTI_LEN = 16;
/** Random bytes behind the broker nonce `non` (Go `NonceLen`). */
export const DELEGATION_NONCE_LEN = 32;

const MANAGED_RE = /^mp:[0-9a-f]{32}$/;

/**
 * @typedef {object} DelegationClaims Go `delegation.Delegation`.
 * @property {string} usr "ed25519:<genesis>" (sovereign) or "mp:<32 hex>" (org-managed)
 * @property {string} org the org's "ed25519:<hex>"
 * @property {string} iss the issuing member key: here a "webauthn:es256:<hex>"
 * @property {string} prn the agent key, "ed25519:<hex>"
 * @property {string} aud the broker's audience
 * @property {string[]} scp scopes; canonicalised (sorted, de-duplicated) here
 * @property {string} jti 16 random bytes, unpadded base64url (newJti)
 * @property {string} non the broker-issued 32-byte nonce, unpadded base64url
 * @property {number | Date} iat issued-at, Unix seconds (or a Date)
 * @property {number | Date} exp expiry, Unix seconds (or a Date)
 */

/**
 * @param {number | Date | undefined | null} t
 * @returns {number | null}
 */
function unixSeconds(t) {
  if (t === undefined || t === null) return null;
  if (t instanceof Date) return Math.floor(t.getTime() / 1000);
  return t;
}

/**
 * Go randomClaim: exactly n bytes in strict unpadded base64url (Go's decoder
 * skips CR/LF even in Strict mode, and this mirrors that).
 * @param {unknown} s
 * @param {number} n
 */
function validRandomClaim(s, n) {
  if (typeof s !== 'string') return false;
  const b = b64urlDecodeStrict(s, { skipNewlines: true });
  return b !== null && b.length === n;
}

/**
 * Go payload.check: the claim grammar shared by mint and parse.
 * @param {{ usr: string, org: string, iss: string, prn: string, aud: string, jti: string, non: string, iat: number, exp: number }} p
 * @returns {{ reason: 'malformed' | 'incomplete' | 'ttl_too_long', why: string } | null}
 */
function checkClaims(p) {
  if (p.usr.startsWith('mp:')) {
    if (!MANAGED_RE.test(p.usr)) return { reason: 'malformed', why: `usr ${JSON.stringify(p.usr)} is not an mp:<32 hex> id` };
  } else if (!isCanonicalEd25519(p.usr)) {
    return { reason: 'malformed', why: 'usr is not a canonical ed25519 key' };
  }
  if (!isCanonicalEd25519(p.org)) return { reason: 'malformed', why: 'org is not a canonical ed25519 key' };
  try {
    parseMemberKey(p.iss);
  } catch {
    return { reason: 'malformed', why: 'iss is not a member key' };
  }
  if (!isCanonicalEd25519(p.prn)) return { reason: 'malformed', why: 'prn is not a canonical ed25519 key' };
  if (p.aud === '') return { reason: 'malformed', why: 'empty aud' };
  if (!validRandomClaim(p.jti, JTI_LEN)) return { reason: 'malformed', why: 'jti is not 16 bytes of unpadded base64url' };
  if (!validRandomClaim(p.non, DELEGATION_NONCE_LEN)) return { reason: 'malformed', why: 'non is not 32 bytes of unpadded base64url' };
  if (p.iat <= 0 || p.exp <= p.iat) return { reason: 'incomplete', why: `the window is empty (iat ${p.iat}, exp ${p.exp})` };
  if (p.exp - p.iat > DELEGATION_MAX_TTL_SECONDS) return { reason: 'ttl_too_long', why: `exp − iat ${p.exp - p.iat}s > 24h` };
  return null;
}

/**
 * @param {{ usr: string, org: string, iss: string, prn: string, aud: string, scp: string[] | null, jti: string, non: string, iat: number, exp: number }} p
 * @returns {Bytes}
 */
function encodePayload(p) {
  return utf8(goJsonMarshal({
    v: DELEGATION_VERSION, typ: DELEGATION_TYP, usr: p.usr, org: p.org, iss: p.iss, prn: p.prn,
    aud: p.aud, scp: p.scp, jti: p.jti, non: p.non, iat: p.iat, exp: p.exp,
  }));
}

/**
 * Go `Delegation.Body`: checks the claims and renders the signed body, the
 * bytes a `webauthn:` issuer asserts over. Scopes are canonicalised here;
 * every other field must already be in its one spelling.
 *
 * Refusals (VoidWhichBindsError.reason): 'incomplete' (a missing binding or an
 * empty window), 'ttl_too_long', 'principal_is_issuer' (prn is iss, usr or
 * org), 'issuer_mismatch' (iss is usr or org), 'malformed' (a claim's grammar,
 * or a scope).
 *
 * @param {DelegationClaims} d
 * @returns {Bytes}
 */
export function delegationBody(d) {
  const iat = unixSeconds(d.iat);
  const exp = unixSeconds(d.exp);
  for (const k of /** @type {const} */ (['usr', 'org', 'iss', 'prn', 'aud', 'jti', 'non'])) {
    if (typeof d[k] !== 'string' || d[k] === '') throw new VoidWhichBindsError('incomplete', `${k} is empty`);
  }
  if (iat === null || exp === null) throw new VoidWhichBindsError('incomplete', 'a delegation needs an issued-at and an expiry');
  if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp)) {
    throw new VoidWhichBindsError('malformed', 'iat and exp are whole Unix seconds');
  }
  const scp = canonicalScopeList(d.scp);
  const p = { usr: d.usr, org: d.org, iss: d.iss, prn: d.prn, aud: d.aud, scp, jti: d.jti, non: d.non, iat, exp };
  if (p.prn === p.iss || p.prn === p.usr || p.prn === p.org) {
    throw new VoidWhichBindsError('principal_is_issuer', `prn ${p.prn} is the issuer, the person or the org`);
  }
  if (p.iss === p.usr || p.iss === p.org) {
    throw new VoidWhichBindsError('issuer_mismatch', `iss ${p.iss} is a genesis key, never a member key`);
  }
  const bad = checkClaims(p);
  if (bad) throw new VoidWhichBindsError(bad.reason, bad.why);
  return encodePayload(p);
}

/**
 * Go `delegation.Challenge(body)`: webAuthnChallenge("void-which-binds.delegation", body),
 * the 32 bytes a passkey issuer passes as the WebAuthn challenge.
 * @param {Uint8Array} body
 * @returns {Promise<Bytes>}
 */
export function delegationChallenge(body) {
  return webAuthnChallenge(DELEGATION_DOMAIN, body);
}

/**
 * Go parseBody: the typ (wrong_type), then the exact canonical encoding and
 * every claim (malformed). Returns the claims.
 * @param {Uint8Array} body
 * @returns {{ usr: string, org: string, iss: string, prn: string, aud: string, scp: string[], jti: string, non: string, iat: number, exp: number }}
 * @throws {VoidWhichBindsError} reason 'wrong_type' or 'malformed'
 */
export function parseDelegationBody(body) {
  const malformed = (/** @type {string} */ why) => new VoidWhichBindsError('malformed', why);
  /** @type {unknown} */
  let o;
  try {
    o = JSON.parse(decodeUtf8Lossy(body));
  } catch {
    throw malformed('the body is not JSON');
  }
  if (o === null || typeof o !== 'object' || Array.isArray(o)) throw malformed('the body is not a JSON object');
  const obj = /** @type {Record<string, unknown>} */ (o);
  // sigtoken.CheckTyp: a case-variant of "typ", or a non-string typ, is malformed;
  // a missing or different typ is wrong_type.
  for (const k of Object.keys(obj)) {
    if (k !== 'typ' && k.toLowerCase() === 'typ') throw malformed('a typ claim in another case');
  }
  if ('typ' in obj && typeof obj.typ !== 'string') throw malformed('typ is not a string');
  if (obj.typ !== DELEGATION_TYP) throw new VoidWhichBindsError('wrong_type', `typ is ${JSON.stringify(obj.typ)}`);
  const str = (/** @type {string} */ k) => {
    const v = obj[k];
    if (v === undefined) return '';
    if (typeof v !== 'string') throw malformed(`${k} is not a string`);
    return v;
  };
  const int = (/** @type {string} */ k) => {
    const v = obj[k];
    if (v === undefined) return 0;
    if (typeof v !== 'number' || !Number.isSafeInteger(v)) throw malformed(`${k} is not an integer`);
    return v;
  };
  const scpRaw = obj.scp;
  if (scpRaw !== undefined && scpRaw !== null && !(Array.isArray(scpRaw) && scpRaw.every((x) => typeof x === 'string'))) {
    throw malformed('scp is not a list of strings');
  }
  const p = {
    v: int('v'), usr: str('usr'), org: str('org'), iss: str('iss'), prn: str('prn'), aud: str('aud'),
    scp: /** @type {string[] | null} */ (scpRaw ?? null), jti: str('jti'), non: str('non'), iat: int('iat'), exp: int('exp'),
  };
  let canon;
  try {
    canon = utf8(goJsonMarshal({
      v: p.v, typ: DELEGATION_TYP, usr: p.usr, org: p.org, iss: p.iss, prn: p.prn, aud: p.aud,
      scp: p.scp, jti: p.jti, non: p.non, iat: p.iat, exp: p.exp,
    }));
  } catch {
    throw malformed('the claims have no canonical encoding');
  }
  if (!bytesEqual(canon, body)) throw malformed('the body is not the canonical encoding of its claims');
  if (p.v !== DELEGATION_VERSION) throw malformed(`v is ${p.v}`);
  if (!isCanonicalScopeList(p.scp)) throw malformed('scp is not a canonical scope list');
  const bad = checkClaims(p);
  if (bad) throw malformed(bad.why);
  return { usr: p.usr, org: p.org, iss: p.iss, prn: p.prn, aud: p.aud, scp: /** @type {string[]} */ (p.scp), jti: p.jti, non: p.non, iat: p.iat, exp: p.exp };
}

/**
 * Go `delegation.AssembleWebAuthn(body, envelope)`: joins a delegation body and
 * the assertion envelope (assembleEnvelope) a passkey issuer produced over
 * delegationChallenge(body) into the token base64url(body) "." base64url(envelope).
 *
 * It checks that body is a well-formed delegation whose iss is a `webauthn:`
 * key ('wrong_type', 'malformed', 'issuer_mismatch') and that the envelope is
 * non-empty ('incomplete'). It does not verify the assertion; the broker does.
 * @param {ArrayBuffer | ArrayBufferView} body
 * @param {ArrayBuffer | ArrayBufferView} envelope
 * @returns {string}
 */
export function assembleDelegationWebAuthn(body, envelope) {
  const b = toBytes(body);
  const env = toBytes(envelope);
  const p = parseDelegationBody(b);
  let kind = null;
  try {
    kind = parseMemberKey(p.iss).kind;
  } catch {
    kind = null;
  }
  if (kind !== KIND_WEBAUTHN) throw new VoidWhichBindsError('issuer_mismatch', `iss ${JSON.stringify(p.iss)} is not a webauthn key`);
  if (env.length === 0) throw new VoidWhichBindsError('incomplete', 'no assertion envelope');
  return b64url(b) + '.' + b64url(env);
}

/**
 * Go `delegation.NewJTI`: 16 random bytes (WebCrypto), unpadded base64url.
 * @returns {string}
 */
export function newJti() {
  return b64url(globalThis.crypto.getRandomValues(new Uint8Array(JTI_LEN)));
}
