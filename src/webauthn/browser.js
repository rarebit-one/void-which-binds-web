// The thin navigator.credentials wrapper. Everything protocol-shaped lives in
// the pure modules (testable in Node); this file only sets the ceremony options
// ADR-0018 requires and hands the browser's bytes to them.
//
// `credentials` is injectable (defaults to navigator.credentials) so a test or
// a non-window host can supply its own CredentialsContainer.

import { b64url, toBytes } from './bytes.js';
import { VoidWhichBindsError } from './errors.js';
import { strictObject } from './json.js';
import { assembleEnvelope, COSE_ALG_ES256, memberKeyFromSpki } from './memberkey.js';

/** @typedef {import('./bytes.js').Bytes} Bytes */

/**
 * @typedef {object} CredentialsLike
 * @property {(opts: any) => Promise<any>} get
 * @property {(opts: any) => Promise<any>} create
 */

/**
 * @param {CredentialsLike | undefined} credentials
 * @returns {CredentialsLike}
 */
function container(credentials) {
  const c = credentials ?? (globalThis.navigator && /** @type {any} */ (globalThis.navigator).credentials);
  if (!c) throw new Error('void-which-binds-web: navigator.credentials is not available (WebAuthn needs a secure context)');
  return c;
}

/**
 * @param {ArrayBuffer | ArrayBufferView | { id: ArrayBuffer | ArrayBufferView, transports?: string[] }} c
 */
function descriptor(c) {
  if (c instanceof ArrayBuffer || ArrayBuffer.isView(c)) return { type: 'public-key', id: toBytes(c) };
  const d = /** @type {{ type: string, id: Bytes, transports?: string[] }} */ ({ type: 'public-key', id: toBytes(c.id) });
  if (c.transports) d.transports = [...c.transports];
  return d;
}

/**
 * @typedef {object} PasskeyAssertion
 * @property {Bytes} envelope the ADR-0018 envelope bytes (assembleEnvelope)
 * @property {Bytes} credentialId rawId
 * @property {Bytes} authenticatorData
 * @property {Bytes} clientDataJSON
 * @property {Bytes} signature DER
 * @property {Bytes | null} userHandle
 */

/**
 * Asks a passkey to assert over `challenge` (one of the pure builders'
 * outputs: delegationChallenge, passkeyChallenge, fetchPasskeyChallenge) with
 * userVerification "required", and returns the assembled envelope.
 *
 * Before returning, it checks that clientDataJSON is a webauthn.get over
 * exactly this challenge, so a confused or hostile page cannot hand back an
 * assertion over something else.
 *
 * @param {object} o
 * @param {string} o.rpId the RP ID (the broker's host, ADR-0018)
 * @param {Uint8Array} o.challenge the 32-byte challenge
 * @param {Array<ArrayBuffer | ArrayBufferView | { id: ArrayBuffer | ArrayBufferView, transports?: string[] }>} [o.allowCredentials]
 *   credential IDs that may answer (empty: a discoverable credential is chosen)
 * @param {number} [o.timeout] ms
 * @param {AbortSignal} [o.signal]
 * @param {string} [o.mediation]
 * @param {CredentialsLike} [o.credentials] defaults to navigator.credentials
 * @returns {Promise<PasskeyAssertion>}
 */
export async function getPasskeyAssertion(o) {
  if (!(o.challenge instanceof Uint8Array) || o.challenge.length !== 32) {
    throw new VoidWhichBindsError('malformed', 'the challenge is 32 bytes');
  }
  if (typeof o.rpId !== 'string' || o.rpId === '') throw new VoidWhichBindsError('malformed', 'an rpId is required');
  /** @type {any} */
  const publicKey = {
    challenge: toBytes(o.challenge),
    rpId: o.rpId,
    userVerification: 'required',
    allowCredentials: (o.allowCredentials ?? []).map(descriptor),
  };
  if (o.timeout !== undefined) publicKey.timeout = o.timeout;
  /** @type {any} */
  const req = { publicKey };
  if (o.signal) req.signal = o.signal;
  if (o.mediation) req.mediation = o.mediation;
  const cred = await container(o.credentials).get(req);
  if (!cred || cred.type !== 'public-key' || !cred.response) {
    throw new VoidWhichBindsError('malformed', 'the browser returned no public-key credential');
  }
  const r = cred.response;
  const authenticatorData = toBytes(r.authenticatorData);
  const clientDataJSON = toBytes(r.clientDataJSON);
  const signature = toBytes(r.signature);
  checkClientData(clientDataJSON, 'webauthn.get', o.challenge);
  return {
    envelope: assembleEnvelope({ authenticatorData, clientDataJSON, signature }),
    credentialId: toBytes(cred.rawId),
    authenticatorData,
    clientDataJSON,
    signature,
    userHandle: r.userHandle ? toBytes(r.userHandle) : null,
  };
}

/**
 * @param {Uint8Array} clientDataJSON
 * @param {string} type
 * @param {Uint8Array} challenge
 */
function checkClientData(clientDataJSON, type, challenge) {
  let b = clientDataJSON;
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) b = b.subarray(3);
  const r = strictObject(b);
  const t = r.ok ? r.members.get('type') : undefined;
  const c = r.ok ? r.members.get('challenge') : undefined;
  if (!t || t.t !== 'str' || t.v !== type) throw new VoidWhichBindsError('wrong_ceremony', `clientDataJSON is not a ${type}`);
  if (!c || c.t !== 'str' || c.v !== b64url(challenge)) {
    throw new VoidWhichBindsError('challenge_mismatch', 'clientDataJSON is over a different challenge');
  }
}

/**
 * @typedef {object} RegisteredPasskey
 * @property {string} memberKey "webauthn:es256:<130 hex>", the ADR-0018 key to enrol
 * @property {Bytes} credentialId rawId
 * @property {Bytes} spki getPublicKey()'s SubjectPublicKeyInfo
 * @property {Bytes} clientDataJSON
 * @property {Bytes} attestationObject
 * @property {string[]} transports getTransports(), when the browser has it
 * @property {boolean | null} backupEligible the BE flag (a synced passkey), when
 *   the browser exposes getAuthenticatorData(); ADR-0018 admits a synced
 *   passkey only for an org-managed person
 * @property {boolean | null} discoverable the credProps extension's `rk`: true
 *   only when the browser reports a discoverable (resident) credential, null
 *   when it reports nothing. The enrolment ceremony submits no key unless it
 *   is true (ADR-0018, "Enrolment proof")
 */

/**
 * The PublicKeyCredentialCreationOptions ADR-0018 registers with: a
 * discoverable credential (residentKey "required"), userVerification
 * "required", ES256 (COSE -7) only, attestation "none", and the credProps
 * extension so the browser reports whether the credential is discoverable.
 * Pure, so a test can pin the exact options.
 *
 * @param {object} o
 * @param {{ id: string, name: string }} o.rp
 * @param {{ id: ArrayBuffer | ArrayBufferView, name: string, displayName: string }} o.user
 * @param {Uint8Array} o.challenge
 * @param {Array<ArrayBuffer | ArrayBufferView | { id: ArrayBuffer | ArrayBufferView, transports?: string[] }>} [o.excludeCredentials]
 * @param {number} [o.timeout]
 * @returns {any}
 */
export function registrationOptions(o) {
  /** @type {any} */
  const publicKey = {
    rp: { id: o.rp.id, name: o.rp.name },
    user: { id: toBytes(o.user.id), name: o.user.name, displayName: o.user.displayName },
    challenge: toBytes(o.challenge),
    pubKeyCredParams: [{ type: 'public-key', alg: COSE_ALG_ES256 }],
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    attestation: 'none',
    excludeCredentials: (o.excludeCredentials ?? []).map(descriptor),
    extensions: { credProps: true },
  };
  if (o.timeout !== undefined) publicKey.timeout = o.timeout;
  return publicKey;
}

/**
 * Registers a discoverable ES256 passkey with user verification required
 * (registrationOptions) and returns its ADR-0018 member key (memberKeyFromSpki
 * over getPublicKey()). A credential that is not ES256 or not P-256 is refused.
 * The challenge and user handle come from the server (an opaque registration
 * challenge); attestation is not requested.
 *
 * @param {object} o
 * @param {{ id: string, name: string }} o.rp
 * @param {{ id: ArrayBuffer | ArrayBufferView, name: string, displayName: string }} o.user
 * @param {Uint8Array} o.challenge
 * @param {Array<ArrayBuffer | ArrayBufferView | { id: ArrayBuffer | ArrayBufferView, transports?: string[] }>} [o.excludeCredentials]
 * @param {number} [o.timeout]
 * @param {AbortSignal} [o.signal]
 * @param {CredentialsLike} [o.credentials]
 * @returns {Promise<RegisteredPasskey>}
 */
export async function createPasskey(o) {
  /** @type {any} */
  const req = { publicKey: registrationOptions(o) };
  if (o.signal) req.signal = o.signal;
  const cred = await container(o.credentials).create(req);
  if (!cred || cred.type !== 'public-key' || !cred.response) {
    throw new VoidWhichBindsError('malformed', 'the browser returned no public-key credential');
  }
  const r = cred.response;
  if (typeof r.getPublicKey !== 'function' || typeof r.getPublicKeyAlgorithm !== 'function') {
    throw new VoidWhichBindsError('malformed', 'this browser does not expose getPublicKey(); the member key cannot be read');
  }
  if (r.getPublicKeyAlgorithm() !== COSE_ALG_ES256) {
    throw new VoidWhichBindsError('malformed', `the credential is COSE alg ${r.getPublicKeyAlgorithm()}, not ES256 (-7)`);
  }
  const spkiBuf = r.getPublicKey();
  if (!spkiBuf) throw new VoidWhichBindsError('malformed', 'getPublicKey() returned no key');
  const spki = toBytes(spkiBuf);
  const clientDataJSON = toBytes(r.clientDataJSON);
  let backupEligible = null;
  if (typeof r.getAuthenticatorData === 'function') {
    const ad = toBytes(r.getAuthenticatorData());
    if (ad.length >= 33) backupEligible = (ad[32] & 0x08) !== 0;
  }
  let discoverable = null;
  if (typeof cred.getClientExtensionResults === 'function') {
    const ext = cred.getClientExtensionResults();
    const rk = ext && ext.credProps ? ext.credProps.rk : undefined;
    if (typeof rk === 'boolean') discoverable = rk;
  }
  return {
    memberKey: memberKeyFromSpki(spki),
    credentialId: toBytes(cred.rawId),
    spki,
    clientDataJSON,
    attestationObject: toBytes(r.attestationObject),
    transports: typeof r.getTransports === 'function' ? [...r.getTransports()] : [],
    backupEligible,
    discoverable,
  };
}
