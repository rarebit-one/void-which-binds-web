// ADR-0018 member keys and WebAuthn assertions: a port of void-which-binds-go
// identity/memberkey.go and identity/webauthn.go (v0.22.0).
//
// - parseMemberKey / formatWebAuthnES256 / memberKeyFromSpki: the
//   `ed25519:<64 hex>` and `webauthn:es256:<130 hex>` key strings, with Go's
//   point validation (crypto/ecdh: uncompressed, on P-256, not the identity).
// - webAuthnChallenge: SHA-256("void-which-binds/webauthn/challenge/v1" ‖ 0 ‖ D ‖ 0 ‖ B).
// - assembleEnvelope: an assertion's {"ad","cd","sig"} envelope.
// - verifyMemberSignature / verifyWebAuthnEnvelope: MemberKey.VerifyBody with
//   ADR-0018's §7.2 checks in Go's order, returning Go's refusal word. The
//   broker stays the authority; this lets a client (and the vector suite)
//   check an assertion before it is sent.

import {
  b64url, b64urlDecodeStrict, bytesEqual, concat, fromHex, sha256, subtle, toBytes, toHex, utf8, validUtf8,
} from './bytes.js';
import { VoidWhichBindsError } from './errors.js';
import { envelopeJson, strictObject } from './json.js';

/** @typedef {import('./bytes.js').Bytes} Bytes */
/** @typedef {import('./json.js').JsonNode} JsonNode */

/** The label ADR-0018's challenge derivation starts with (Go `WebAuthnChallengeLabel`). */
export const WEBAUTHN_CHALLENGE_LABEL = 'void-which-binds/webauthn/challenge/v1';

/** Member-key kinds (Go `KindEd25519`, `KindWebAuthn`). */
export const KIND_ED25519 = 'ed25519';
export const KIND_WEBAUTHN = 'webauthn';

/** The COSE algorithm a `webauthn:es256:` key was registered with (ES256). */
export const COSE_ALG_ES256 = -7;

// P-256 (SEC 2 / FIPS 186-4).
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_POINT_LEN = 65;

/**
 * @typedef {{ kind: 'ed25519', text: string, raw: Bytes }
 *   | { kind: 'webauthn', text: string, point: Bytes }} MemberKey
 */

/**
 * @typedef {object} WebAuthnRP
 * @property {string} rpId
 * @property {string[]} origins
 */

/**
 * @typedef {object} WebAuthnPolicy Go `identity.WebAuthnPolicy`.
 * @property {WebAuthnRP[]} rps the allow-list of {RP ID, origins} pairs
 * @property {boolean} [allowSynced] admit a backup-eligible (synced) passkey;
 *   only for an org-managed person (ADR-0018, fail closed)
 */

/**
 * @param {Uint8Array} b
 * @returns {bigint}
 */
function toBig(b) {
  return BigInt('0x' + (toHex(b) || '0'));
}

/**
 * Go's crypto/ecdh P256().NewPublicKey rule: 65 bytes, 0x04 prefix, both
 * coordinates reduced mod p, on y² = x³ − 3x + b, and therefore not the
 * identity (which has no affine encoding and fails the equation).
 * @param {Uint8Array} point
 * @returns {boolean}
 */
export function isValidP256Point(point) {
  if (point.length !== P256_POINT_LEN || point[0] !== 0x04) return false;
  const x = toBig(point.subarray(1, 33));
  const y = toBig(point.subarray(33, 65));
  if (x >= P || y >= P) return false;
  const lhs = (y * y) % P;
  const rhs = (((x * x) % P) * x - 3n * x + B) % P;
  return lhs === ((rhs % P) + P) % P;
}

/**
 * Go `identity.ParseMemberKey`: "ed25519:<64 lowercase hex>" or
 * "webauthn:es256:<130 lowercase hex>" (an uncompressed P-256 point on the
 * curve). No surrounding whitespace; any other prefix is refused.
 * @param {string} s
 * @returns {MemberKey}
 * @throws {VoidWhichBindsError} reason 'malformed'
 */
export function parseMemberKey(s) {
  const bad = (/** @type {string} */ why) => new VoidWhichBindsError('malformed', `member key ${JSON.stringify(s)}: ${why}`);
  if (typeof s !== 'string' || s === '') throw bad('empty');
  if (s.trim() !== s) throw bad('surrounding whitespace');
  const colon = s.indexOf(':');
  if (colon < 0) throw bad('no key-kind prefix');
  const prefix = s.slice(0, colon);
  const rest = s.slice(colon + 1);
  if (prefix === KIND_ED25519) {
    // ParsePublicKey on an already-untrimmed string: lowercase hex, 32 bytes.
    if (rest !== rest.toLowerCase()) throw bad('not lowercase hex');
    const raw = fromHex(rest);
    if (!raw) throw bad('not hex');
    if (raw.length !== 32) throw bad(`decodes to ${raw.length} bytes, and an ed25519 key is 32`);
    return { kind: KIND_ED25519, text: s, raw };
  }
  if (prefix === KIND_WEBAUTHN) {
    const c2 = rest.indexOf(':');
    if (c2 < 0 || rest.slice(0, c2) !== 'es256') throw bad('a webauthn key without the "es256" sub-algorithm');
    const hexed = rest.slice(c2 + 1);
    if (hexed.length !== 2 * P256_POINT_LEN) throw bad(`${hexed.length} hex characters, and a webauthn:es256 key has 130`);
    if (hexed !== hexed.toLowerCase()) throw bad('not lowercase hex');
    const point = fromHex(hexed);
    if (!point) throw bad('not hex');
    if (!isValidP256Point(point)) throw bad('not a valid P-256 point');
    return { kind: KIND_WEBAUTHN, text: s, point };
  }
  throw bad(`names key kind ${JSON.stringify(prefix)}; a member key is "ed25519" or "webauthn" (ADR-0018)`);
}

/**
 * Go `identity.ParseCanonicalPublicKey`: exactly "ed25519:<64 lowercase hex>".
 * @param {string} s
 * @returns {boolean}
 */
export function isCanonicalEd25519(s) {
  return typeof s === 'string' && /^ed25519:[0-9a-f]{64}$/.test(s);
}

/**
 * Go `identity.FormatWebAuthnES256`, plus the validation Go leaves to
 * ParseMemberKey: a 65-byte uncompressed P-256 point → "webauthn:es256:<130
 * lowercase hex>". A point that is compressed, off the curve or the identity is
 * refused, so the result always parses.
 * @param {ArrayBuffer | ArrayBufferView} point
 * @returns {string}
 * @throws {VoidWhichBindsError} reason 'malformed'
 */
export function formatWebAuthnES256(point) {
  const p = toBytes(point);
  if (!isValidP256Point(p)) {
    throw new VoidWhichBindsError('malformed', 'not a 65-byte uncompressed P-256 point on the curve');
  }
  return `${KIND_WEBAUTHN}:es256:${toHex(p)}`;
}

// SubjectPublicKeyInfo DER for an id-ecPublicKey on prime256v1 with an
// uncompressed point: SEQUENCE { SEQUENCE { OID 1.2.840.10045.2.1,
// OID 1.2.840.10045.3.1.7 }, BIT STRING (0 unused bits) 04‖X‖Y }. It is the
// one encoding a browser's AuthenticatorAttestationResponse.getPublicKey()
// returns for an ES256 credential.
const P256_SPKI_PREFIX = fromHex('3059301306072a8648ce3d020106082a8648ce3d030107034200');

/**
 * Registration: the SPKI DER from AuthenticatorAttestationResponse
 * .getPublicKey() of an ES256 (COSE -7) credential → its ADR-0018 member key,
 * "webauthn:es256:<130 lowercase hex>". Only the exact 91-byte P-256
 * uncompressed SPKI is accepted, and the point is validated as Go's
 * ParseMemberKey validates it.
 * @param {ArrayBuffer | ArrayBufferView} spki
 * @returns {string}
 * @throws {VoidWhichBindsError} reason 'malformed'
 */
export function memberKeyFromSpki(spki) {
  const b = toBytes(spki);
  const prefix = /** @type {Bytes} */ (P256_SPKI_PREFIX);
  if (b.length !== prefix.length + P256_POINT_LEN || !bytesEqual(b.subarray(0, prefix.length), prefix)) {
    throw new VoidWhichBindsError('malformed', 'not a P-256 SubjectPublicKeyInfo with an uncompressed point (is the credential ES256?)');
  }
  return formatWebAuthnES256(b.subarray(prefix.length));
}

/**
 * Go `identity.checkDomain`: a WebAuthn challenge domain is non-empty and has
 * no NUL, so the derivation frames it unambiguously.
 * @param {string} domain
 */
export function checkDomain(domain) {
  if (typeof domain !== 'string' || domain === '' || domain.includes('\u0000')) {
    throw new VoidWhichBindsError('malformed', `the webauthn challenge domain ${JSON.stringify(domain)} is empty or contains NUL`);
  }
}

/**
 * Go `identity.WebAuthnChallenge(domain, body)`:
 *
 *     SHA-256( "void-which-binds/webauthn/challenge/v1" ‖ 0x00 ‖ domain ‖ 0x00 ‖ body )
 *
 * The 32 bytes are PublicKeyCredentialRequestOptions.challenge (with
 * userVerification "required"). The domain is checked as VerifyBody checks it.
 * @param {string} domain
 * @param {Uint8Array} body
 * @returns {Promise<Bytes>}
 */
export async function webAuthnChallenge(domain, body) {
  checkDomain(domain);
  return sha256(concat(utf8(WEBAUTHN_CHALLENGE_LABEL), Uint8Array.of(0), utf8(domain), Uint8Array.of(0), body));
}

/**
 * The ADR-0018 assertion envelope a `webauthn:` signature segment carries:
 * {"ad":<b64url authenticatorData>,"cd":<b64url clientDataJSON>,"sig":<b64url DER>},
 * byte-identical to what void-which-binds-go verifies.
 *
 * Inputs are the AuthenticatorAssertionResponse fields as the browser returns
 * them, unmodified (the signature covers the clientDataJSON bytes as sent). The
 * signature must be the DER Ecdsa-Sig-Value WebAuthn returns for ES256; a raw
 * 64-byte r ‖ s (WebCrypto's form) is refused here, because Go would refuse it
 * as bad_signature.
 *
 * @param {{ authenticatorData: ArrayBuffer | ArrayBufferView, clientDataJSON: ArrayBuffer | ArrayBufferView, signature: ArrayBuffer | ArrayBufferView }} assertion
 * @returns {Bytes} the envelope's UTF-8 bytes
 * @throws {VoidWhichBindsError} reason 'malformed'
 */
export function assembleEnvelope(assertion) {
  const ad = toBytes(assertion.authenticatorData);
  const cd = toBytes(assertion.clientDataJSON);
  const sig = toBytes(assertion.signature);
  if (ad.length === 0 || cd.length === 0 || sig.length === 0) {
    throw new VoidWhichBindsError('malformed', 'authenticatorData, clientDataJSON and signature are all required');
  }
  if (!parseDerSignature(sig)) {
    throw new VoidWhichBindsError('malformed', 'the signature is not a strict DER ECDSA signature (WebAuthn ES256 returns DER)');
  }
  const env = utf8(envelopeJson(ad, cd, sig));
  if (env.length > MAX_ENVELOPE_LEN) {
    throw new VoidWhichBindsError('malformed', `the envelope is ${env.length} bytes, over ${MAX_ENVELOPE_LEN}`);
  }
  return env;
}

// --- verification (Go MemberKey.VerifyBody) ---------------------------------------

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;
const AUTH_DATA_MIN_LEN = 37;
/** Go `maxEnvelopeLen`: the envelope bound, checked before any parsing. */
export const MAX_ENVELOPE_LEN = 16 << 10;

/** A refusal inside the verifier: carries ADR-0018's word. */
class Refusal extends Error {
  /** @param {string} word @param {string} why */
  constructor(word, why) {
    super(why);
    this.word = word;
  }
}

/**
 * Parses a DER Ecdsa-Sig-Value exactly as Go's ecdsa.VerifyASN1 does
 * (cryptobyte: definite minimal lengths, minimal INTEGERs, nothing trailing),
 * and requires r, s in [1, n−1].
 * @param {Uint8Array} der
 * @returns {Bytes | null} the fixed-width r ‖ s (64 bytes) WebCrypto verifies, or null
 */
export function parseDerSignature(der) {
  let i = 0;
  /** @param {Uint8Array} b @param {number} tag @returns {Uint8Array | null} */
  const readTLV = (b, tag) => {
    if (i >= b.length || b[i] !== tag) return null;
    i++;
    if (i >= b.length) return null;
    let len = b[i++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4 || i + n > b.length) return null;
      if (b[i] === 0) return null; // non-minimal length bytes
      len = 0;
      for (let k = 0; k < n; k++) len = len * 256 + b[i++];
      if (len < 0x80) return null; // long form for a short length
    }
    if (i + len > b.length) return null;
    const v = b.subarray(i, i + len);
    i += len;
    return v;
  };
  const seq = readTLV(der, 0x30);
  if (!seq || i !== der.length) return null;
  i = 0;
  const r = readTLV(seq, 0x02);
  const s = readTLV(seq, 0x02);
  if (!r || !s || i !== seq.length) return null;
  /** @param {Uint8Array} v @returns {bigint | null} */
  const asInt = (v) => {
    if (v.length === 0) return null;
    if (v.length > 1 && ((v[0] === 0x00 && (v[1] & 0x80) === 0) || (v[0] === 0xff && (v[1] & 0x80) !== 0))) return null;
    if (v[0] & 0x80) return -1n; // negative: out of range below
    return toBig(v);
  };
  const rn = asInt(r);
  const sn = asInt(s);
  if (rn === null || sn === null || rn < 1n || sn < 1n || rn >= N || sn >= N) return null;
  const out = new Uint8Array(64);
  out.set(fromHex(rn.toString(16).padStart(64, '0')) ?? new Uint8Array(32), 0);
  out.set(fromHex(sn.toString(16).padStart(64, '0')) ?? new Uint8Array(32), 32);
  return out;
}

/**
 * @param {JsonNode | undefined} node
 * @returns {string | null}
 */
function jsonString(node) {
  return node && node.t === 'str' ? node.v : null;
}

/**
 * Go parseEnvelope.
 * @param {Uint8Array} seg
 */
function parseEnvelope(seg) {
  if (seg.length > MAX_ENVELOPE_LEN) {
    throw new Refusal('malformed', `the envelope is ${seg.length} bytes, over ${MAX_ENVELOPE_LEN}`);
  }
  let k = 0;
  while (k < seg.length && (seg[k] === 0x20 || seg[k] === 0x09 || seg[k] === 0x0d || seg[k] === 0x0a)) k++;
  const r = strictObject(seg);
  if (k === seg.length || seg[k] !== 0x7b || (!r.ok && r.syntax)) {
    throw new Refusal('bad_signature', 'the signature segment is not a webauthn assertion envelope');
  }
  if (!r.ok) throw new Refusal('malformed', `envelope: ${r.why}`);
  if (r.members.size !== 3) throw new Refusal('malformed', 'the envelope must have exactly ad, cd and sig');
  /** @type {Record<string, Bytes>} */
  const out = {};
  for (const name of ['ad', 'cd', 'sig']) {
    const node = r.members.get(name);
    if (!node) throw new Refusal('malformed', `the envelope has no "${name}"`);
    const s = jsonString(node);
    if (s === null) throw new Refusal('malformed', `envelope "${name}" is not a string`);
    if (/[\r\n]/.test(s)) throw new Refusal('malformed', `envelope "${name}" is not unpadded base64url`);
    const b = b64urlDecodeStrict(s);
    if (!b || b.length === 0) throw new Refusal('malformed', `envelope "${name}" is not unpadded base64url`);
    out[name] = b;
  }
  return { authData: out.ad, clientData: out.cd, sig: out.sig };
}

/**
 * Go parseClientData (§7.2 steps 7–9).
 * @param {Uint8Array} raw
 */
function parseClientData(raw) {
  let b = raw;
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) b = b.subarray(3);
  if (!validUtf8(b)) throw new Refusal('malformed', 'clientDataJSON is not UTF-8');
  const r = strictObject(b);
  if (!r.ok) throw new Refusal('malformed', `clientDataJSON: ${r.why}`);
  /** @type {Record<string, string>} */
  const cd = {};
  for (const name of ['type', 'challenge', 'origin']) {
    const s = jsonString(r.members.get(name));
    if (s === null) throw new Refusal('malformed', `clientDataJSON "${name}" is missing or not a string`);
    cd[name] = s;
  }
  let crossOrigin = false;
  const co = r.members.get('crossOrigin');
  if (co) {
    if (co.t !== 'bool') throw new Refusal('malformed', 'clientDataJSON crossOrigin is not a boolean');
    crossOrigin = co.v;
  }
  return { type: cd.type, challenge: cd.challenge, origin: cd.origin, crossOrigin, hasTopOrigin: r.members.has('topOrigin') };
}

/**
 * Go checkAuthDataLayout.
 * @param {Uint8Array} ad
 */
function checkAuthDataLayout(ad) {
  if (ad.length < AUTH_DATA_MIN_LEN) {
    throw new Refusal('malformed', `authenticatorData is ${ad.length} bytes, under ${AUTH_DATA_MIN_LEN}`);
  }
  const flags = ad[32];
  if (flags & FLAG_AT) throw new Refusal('malformed', 'AT (attested credential data) is set on an assertion');
  if (!(flags & FLAG_ED) && ad.length !== AUTH_DATA_MIN_LEN) {
    throw new Refusal('malformed', 'authenticatorData has trailing bytes and no ED flag');
  }
  if (flags & FLAG_ED && ad.length === AUTH_DATA_MIN_LEN) {
    throw new Refusal('malformed', 'ED is set and no extension data follows');
  }
}

/**
 * Go MemberKey.verifyWebAuthn: structural checks first (envelope, then
 * clientDataJSON, then the authenticatorData layout), then §7.2 steps 10–21 in
 * order, signature last. signCount is deliberately ignored (ADR-0018).
 * @param {Uint8Array} point
 * @param {Uint8Array} challenge
 * @param {Uint8Array} seg
 * @param {WebAuthnPolicy} pol
 */
async function verifyWebAuthn(point, challenge, seg, pol) {
  const env = parseEnvelope(seg);
  const cd = parseClientData(env.clientData);
  const ad = env.authData;
  checkAuthDataLayout(ad);
  const flags = ad[32];
  if (cd.type !== 'webauthn.get') throw new Refusal('wrong_ceremony', `type is ${JSON.stringify(cd.type)}`);
  if (cd.challenge !== b64url(challenge)) throw new Refusal('challenge_mismatch', 'the assertion is over a different challenge');
  const rpIds = (pol.rps || []).filter((rp) => rp.origins.includes(cd.origin)).map((rp) => rp.rpId);
  if (rpIds.length === 0) throw new Refusal('origin_not_allowed', JSON.stringify(cd.origin));
  if (cd.crossOrigin) throw new Refusal('origin_not_allowed', 'crossOrigin is true');
  if (cd.hasTopOrigin) throw new Refusal('origin_not_allowed', 'topOrigin is present');
  let rpMatch = false;
  for (const id of rpIds) {
    if (bytesEqual(ad.subarray(0, 32), await sha256(utf8(id)))) rpMatch = true;
  }
  if (!rpMatch) throw new Refusal('rp_id_mismatch', `origin ${JSON.stringify(cd.origin)}`);
  if (!(flags & FLAG_UP)) throw new Refusal('user_not_present', 'UP is clear');
  if (!(flags & FLAG_UV)) throw new Refusal('user_not_verified', 'UV is clear');
  if (!(flags & FLAG_BE) && flags & FLAG_BS) throw new Refusal('malformed', 'BS is set without BE');
  if (flags & FLAG_BE && !pol.allowSynced) throw new Refusal('synced_not_allowed', 'a synced (backup-eligible) passkey');
  const rs = parseDerSignature(env.sig);
  if (!rs) throw new Refusal('bad_signature', 'not a DER ECDSA signature');
  const key = await subtle().importKey('raw', /** @type {Bytes} */ (point), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const msg = concat(ad, await sha256(env.clientData));
  const ok = await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rs, msg);
  if (!ok) throw new Refusal('bad_signature', 'ES256 assertion does not verify');
}

/**
 * Runs fn, mapping a refusal to its word and success to 'ok'.
 * @param {() => Promise<void>} fn
 * @returns {Promise<string>}
 */
async function verdict(fn) {
  try {
    await fn();
    return 'ok';
  } catch (e) {
    if (e instanceof Refusal) return e.word;
    if (e instanceof VoidWhichBindsError) return 'malformed';
    throw e;
  }
}

/**
 * Go `MemberKey.VerifyBody` + `MemberKeyReason`: verifies sig as the member
 * key's signature over body for domain, and returns ADR-0018's word: 'ok',
 * 'malformed', 'wrong_ceremony', 'challenge_mismatch', 'origin_not_allowed',
 * 'rp_id_mismatch', 'user_not_present', 'user_not_verified',
 * 'synced_not_allowed' or 'bad_signature'.
 *
 * The scheme comes from the key's kind, never from the shape of sig: an
 * ed25519 key takes the raw 64-byte signature over body (domain and policy
 * unused); a webauthn key takes the envelope, asserted over
 * webAuthnChallenge(domain, body) under policy.
 *
 * @param {string} key the member-key string
 * @param {string} domain
 * @param {Uint8Array} body
 * @param {Uint8Array} sig the signature segment, base64url-decoded
 * @param {WebAuthnPolicy} policy
 * @returns {Promise<string>}
 */
export async function verifyMemberSignature(key, domain, body, sig, policy) {
  return verdict(async () => {
    const mk = parseMemberKey(key);
    if (mk.kind === KIND_ED25519) {
      if (sig.length !== 64) throw new Refusal('bad_signature', 'not a 64-byte ed25519 signature');
      let ok = false;
      try {
        const k = await subtle().importKey('raw', mk.raw, { name: 'Ed25519' }, false, ['verify']);
        ok = await subtle().verify({ name: 'Ed25519' }, k, /** @type {Bytes} */ (sig), /** @type {Bytes} */ (body));
      } catch {
        ok = false; // an undecodable public key verifies nothing, as in Go
      }
      if (!ok) throw new Refusal('bad_signature', 'ed25519 signature does not verify');
      return;
    }
    checkDomain(domain);
    await verifyWebAuthn(mk.point, await webAuthnChallenge(domain, body), sig, policy);
  });
}

/**
 * ADR-0018's checks for an envelope over a RAW challenge (no domain/body
 * derivation): what the spec vectors exercise, and what a client uses to check
 * an assertion it just obtained for a challenge it already derived.
 * @param {string} key a `webauthn:es256:` member-key string
 * @param {Uint8Array} challenge
 * @param {Uint8Array} envelope
 * @param {WebAuthnPolicy} policy
 * @returns {Promise<string>} ADR-0018's word
 */
export async function verifyWebAuthnEnvelope(key, challenge, envelope, policy) {
  return verdict(async () => {
    const mk = parseMemberKey(key);
    if (mk.kind !== KIND_WEBAUTHN) throw new Refusal('bad_signature', 'not a webauthn key');
    await verifyWebAuthn(mk.point, challenge, envelope, policy);
  });
}
