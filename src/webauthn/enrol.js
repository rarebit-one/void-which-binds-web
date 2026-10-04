// The invitee's half of the P5 invite and enrolment ceremony (ADR-0018,
// amended 2026-10-04, "Enrolment proof"; P4–P7 plan §3 steps 2–3):
//
//   begin    the link token → the invite's {rp, user, challenge, org, mem}
//   create   a discoverable, UV-required ES256 passkey (credProps), SPKI →
//            "webauthn:es256:<hex>"; no key is submitted unless credProps.rk
//            is true
//   key      post the key with the link token → the broker's {nonce, iat, exp},
//            issued against this key
//   get      assert over EnrolProof.PasskeyChallenge, allowCredentials = the
//            credential just created, UV required; pre-flight it under the
//            candidate key
//   proof    post the ADR-0018 envelope; the broker rebuilds EnrolProof from
//            its own records, verifies, and drafts set + enrol for cosign
//
// The broker's HTTP shapes are PROPOSED, to be fixed by moneta P5 M2 (see
// DESIGN.md). They sit behind an injectable `transport`, and the default one
// (httpEnrolTransport) only ever calls the `fetch` it is handed: nothing here
// reaches the network on its own.

import { b64url, toBytes } from './bytes.js';
import { VoidWhichBindsError } from './errors.js';
import { createPasskey, getPasskeyAssertion } from './browser.js';
import { decodeCanonical } from './approval.js';
import {
  DOMAIN_ENROL_PROOF, ENROL_PROOF_NONCE_LEN, enrolProofChallenge, enrolProofPreimage, isManagedId,
} from './enrolproof.js';
import { isCanonicalEd25519, verifyMemberSignature } from './memberkey.js';

/** @typedef {import('./bytes.js').Bytes} Bytes */
/** @typedef {import('./browser.js').CredentialsLike} CredentialsLike */

/** The proposed broker paths, relative to its origin (to be fixed by moneta P5 M2). */
export const ENROL_PATHS = Object.freeze({
  begin: '/enrol/begin',
  key: '/enrol/key',
  proof: '/enrol/proof',
});

const malformed = (/** @type {string} */ why) => new VoidWhichBindsError('malformed', why);

/**
 * @typedef {object} EnrolInvite What `begin` yields: the registration options
 *   and the invite's binding.
 * @property {{ id: string, name: string }} rp the RP (rp.id is the broker's host)
 * @property {{ id: Bytes, name: string, displayName: string }} user the
 *   WebAuthn user entity (user.id is the broker's opaque handle, 1–64 bytes)
 * @property {Bytes} challenge the registration challenge (broker-random; no
 *   Go verifier sees the registration response)
 * @property {string} org canonical "ed25519:<64 hex>"
 * @property {string} mem "mp:<32 hex>"
 */

/**
 * @typedef {object} EnrolNonce What `submitKey` yields: the nonce the broker
 *   issued against this key, and its window.
 * @property {Bytes} nonce 32 bytes
 * @property {number} iat Unix seconds
 * @property {number} exp Unix seconds
 */

/**
 * @typedef {object} EnrolTransport The three broker calls. Inject one to speak
 *   another wire; httpEnrolTransport speaks the proposed one.
 * @property {(a: { inviteToken: string, signal?: AbortSignal }) => Promise<EnrolInvite>} begin
 * @property {(a: { inviteToken: string, key: string, signal?: AbortSignal }) => Promise<EnrolNonce>} submitKey
 * @property {(a: { inviteToken: string, key: string, sig: string, signal?: AbortSignal }) => Promise<unknown>} submitProof
 */

/**
 * Checks `origin` is a serialized web origin ("https://host[:port]", nothing
 * after it), the audience the proof binds.
 * @param {unknown} origin
 * @returns {string}
 */
function checkOrigin(origin) {
  if (typeof origin !== 'string' || origin === '') throw malformed('an origin is required');
  let u;
  try {
    u = new URL(origin);
  } catch {
    throw malformed(`origin ${JSON.stringify(origin)} is not a URL`);
  }
  if (u.origin !== origin) throw malformed(`origin ${JSON.stringify(origin)} is not a serialized origin (scheme://host[:port])`);
  return origin;
}

/**
 * @param {unknown} v
 * @returns {v is Record<string, unknown>}
 */
function isObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * @param {unknown} v
 * @param {string} what
 * @returns {string}
 */
function str(v, what) {
  if (typeof v !== 'string' || v === '') throw malformed(`${what} is missing or not a string`);
  return v;
}

/**
 * Parses the proposed begin response:
 * { rp: { id, name }, user: { id: b64url, name, displayName }, challenge: b64url, org, mem }.
 * @param {unknown} j
 * @returns {EnrolInvite}
 */
export function parseEnrolInvite(j) {
  if (!isObject(j) || !isObject(j.rp) || !isObject(j.user)) throw malformed('the invite is not { rp, user, challenge, org, mem }');
  const userId = decodeCanonical(j.user.id);
  if (!userId || userId.length === 0 || userId.length > 64) throw malformed('user.id is not 1 to 64 bytes of base64url');
  const challenge = decodeCanonical(j.challenge);
  if (!challenge || challenge.length < 16) throw malformed('the registration challenge is not at least 16 bytes of base64url');
  const org = str(j.org, 'org');
  const mem = str(j.mem, 'mem');
  if (!isCanonicalEd25519(org)) throw malformed(`org ${JSON.stringify(org)} is not a canonical ed25519 key`);
  if (!isManagedId(mem)) throw malformed(`mem ${JSON.stringify(mem)} is not an "mp:" id`);
  return {
    rp: { id: str(j.rp.id, 'rp.id'), name: str(j.rp.name, 'rp.name') },
    user: { id: userId, name: str(j.user.name, 'user.name'), displayName: str(j.user.displayName, 'user.displayName') },
    challenge,
    org,
    mem,
  };
}

/**
 * Parses the proposed key response: { nonce: b64url(32 bytes), iat, exp }.
 * The window itself is checked when the proof is built.
 * @param {unknown} j
 * @returns {EnrolNonce}
 */
export function parseEnrolNonce(j) {
  if (!isObject(j)) throw malformed('the nonce response is not { nonce, iat, exp }');
  const nonce = decodeCanonical(j.nonce);
  if (!nonce || nonce.length !== ENROL_PROOF_NONCE_LEN) throw malformed(`the nonce is not ${ENROL_PROOF_NONCE_LEN} bytes of base64url`);
  if (!Number.isSafeInteger(j.iat) || !Number.isSafeInteger(j.exp)) throw malformed('iat and exp are whole Unix seconds');
  return { nonce, iat: /** @type {number} */ (j.iat), exp: /** @type {number} */ (j.exp) };
}

/**
 * The default transport: the proposed JSON wire (DESIGN.md, "Invite and
 * enrolment"), each a POST to `baseUrl` + ENROL_PATHS through the injected
 * `fetch`, same-origin credentials, no caching. A non-2xx response is refused
 * with the broker's `{"error": "<word>"}` as the reason when it sends one, or
 * 'enrol_refused' otherwise (`detail` carries the HTTP status).
 *
 * @param {object} o
 * @param {typeof fetch} o.fetch required; there is no ambient default
 * @param {string} o.baseUrl the broker's origin (the PWA's own)
 * @returns {EnrolTransport}
 */
export function httpEnrolTransport(o) {
  if (!o || typeof o.fetch !== 'function') throw new TypeError('void-which-binds-web: httpEnrolTransport needs a fetch');
  const fetchImpl = o.fetch;
  const base = checkOrigin(o.baseUrl);
  /**
   * @param {string} path
   * @param {Record<string, string>} body
   * @param {AbortSignal | undefined} signal
   * @returns {Promise<unknown>}
   */
  const post = async (path, body, signal) => {
    /** @type {RequestInit} */
    const init = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
      cache: 'no-store',
    };
    if (signal) init.signal = signal;
    const res = await fetchImpl(base + path, init);
    let json = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    if (!res.ok) {
      const word = isObject(json) && typeof json.error === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(json.error)
        ? json.error : 'enrol_refused';
      throw new VoidWhichBindsError(word, `POST ${path} → HTTP ${res.status}`, { detail: `http_${res.status}` });
    }
    if (json === null) throw malformed(`POST ${path} returned no JSON`);
    return json;
  };
  return {
    begin: async ({ inviteToken, signal }) => parseEnrolInvite(await post(ENROL_PATHS.begin, { invite: inviteToken }, signal)),
    submitKey: async ({ inviteToken, key, signal }) => parseEnrolNonce(await post(ENROL_PATHS.key, { invite: inviteToken, key }, signal)),
    submitProof: ({ inviteToken, key, sig, signal }) => post(ENROL_PATHS.proof, { invite: inviteToken, key, sig }, signal),
  };
}

/**
 * @typedef {object} EnrolResult
 * @property {string} memberKey the enrolled candidate, "webauthn:es256:<130 hex>"
 * @property {Bytes} credentialId
 * @property {string[]} transports
 * @property {boolean | null} backupEligible the BE flag (a synced passkey)
 * @property {string} org
 * @property {string} mem
 * @property {Bytes} preimage the EnrolProof preimage B the passkey asserted over
 * @property {Bytes} envelope the ADR-0018 envelope posted as the proof
 * @property {unknown} result the broker's response to the proof, as sent
 */

/**
 * The whole invitee ceremony (see the file header): begin → create → post the
 * key → get over the enrol-proof challenge → post the envelope. Two
 * user-verified ceremonies, as ADR-0018 costs it.
 *
 * Fails closed before posting anything it could not stand behind: no key is
 * submitted unless credProps reports a discoverable credential
 * ('not_discoverable'); the nonce response must build a well-formed proof
 * ('malformed'); the assertion must come from the credential just created
 * ('credential_mismatch') and verify under the candidate key for `origin` and
 * the invite's RP ID (ADR-0018's word otherwise). The broker stays the
 * authority on everything, including the window.
 *
 * @param {object} o
 * @param {string} o.origin the broker's origin, the proof's audience (the
 *   PWA's own: location.origin)
 * @param {string} o.inviteToken the single-use link token (a bearer secret)
 * @param {typeof fetch} [o.fetch] required unless `transport` is given
 * @param {EnrolTransport} [o.transport] the broker calls (default:
 *   httpEnrolTransport({ fetch, baseUrl: origin }))
 * @param {CredentialsLike} [o.credentials] defaults to navigator.credentials
 * @param {AbortSignal} [o.signal]
 * @param {number} [o.timeout] ms, for each WebAuthn ceremony
 * @param {(s: { phase: 'begin' | 'create' | 'submit-key' | 'assert' | 'submit-proof' | 'done' }) => void} [o.onStatus]
 * @returns {Promise<EnrolResult>}
 */
export async function enrolWithInvite(o) {
  const origin = checkOrigin(o.origin);
  if (typeof o.inviteToken !== 'string' || o.inviteToken === '') throw malformed('an invite token is required');
  let t = o.transport;
  if (!t) {
    if (typeof o.fetch !== 'function') throw new TypeError('void-which-binds-web: enrolWithInvite needs a fetch or a transport');
    t = httpEnrolTransport({ fetch: o.fetch, baseUrl: origin });
  }
  const status = o.onStatus ?? (() => {});
  const { inviteToken, signal } = o;

  status({ phase: 'begin' });
  const invite = await t.begin({ inviteToken, signal });

  status({ phase: 'create' });
  const reg = await createPasskey({
    rp: invite.rp, user: invite.user, challenge: invite.challenge,
    credentials: o.credentials, signal, timeout: o.timeout,
  });
  if (reg.discoverable !== true) {
    // ADR-0018: credProps.rk absent or false → no key is submitted.
    throw new VoidWhichBindsError('not_discoverable', 'the browser did not report a discoverable credential (credProps.rk); no key was submitted');
  }

  status({ phase: 'submit-key' });
  const issued = await t.submitKey({ inviteToken, key: reg.memberKey, signal });
  const proof = {
    audience: origin, org: invite.org, mem: invite.mem, key: reg.memberKey,
    nonce: toBytes(issued.nonce), issuedAt: issued.iat, expiresAt: issued.exp,
  };
  const preimage = enrolProofPreimage(proof);
  const challenge = await enrolProofChallenge(proof);

  status({ phase: 'assert' });
  const a = await getPasskeyAssertion({
    rpId: invite.rp.id, challenge,
    allowCredentials: [{ id: reg.credentialId, transports: reg.transports }],
    credentials: o.credentials, signal, timeout: o.timeout,
  });
  if (b64url(a.credentialId) !== b64url(reg.credentialId)) {
    throw new VoidWhichBindsError('credential_mismatch', 'the assertion is not from the credential just created');
  }
  // Pre-flight under the candidate key, synced passkeys admitted (an mp:
  // person is org-managed, ADR-0018's default); the broker re-verifies.
  const word = await verifyMemberSignature(reg.memberKey, DOMAIN_ENROL_PROOF, preimage, a.envelope, {
    rps: [{ rpId: invite.rp.id, origins: [origin] }], allowSynced: true,
  });
  if (word !== 'ok') throw new VoidWhichBindsError(word, 'the enrol proof does not verify under the candidate key');

  status({ phase: 'submit-proof' });
  const result = await t.submitProof({ inviteToken, key: reg.memberKey, sig: b64url(a.envelope), signal });

  status({ phase: 'done' });
  return {
    memberKey: reg.memberKey,
    credentialId: reg.credentialId,
    transports: reg.transports,
    backupEligible: reg.backupEligible,
    org: invite.org,
    mem: invite.mem,
    preimage,
    envelope: a.envelope,
    result,
  };
}
