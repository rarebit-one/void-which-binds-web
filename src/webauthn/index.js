// @rarebit-one/void-which-binds-web/webauthn — the browser WebAuthn (passkey)
// signer for Void-Which-Binds member keys (ADR-0018).
//
// Pure, Node-testable builders mirror void-which-binds-go byte for byte; the
// navigator.credentials wrapper is kept apart in browser.js. WebCrypto only,
// no runtime dependencies. Golden vectors: test/vectors (pinned to a
// void-which-binds-go commit in test/vectors/VOID_WHICH_BINDS_GO_REF).

export { VoidWhichBindsError } from './errors.js';
export { b64url, b64urlDecodeStrict, fromHex, toHex } from './bytes.js';
export {
  COSE_ALG_ES256,
  KIND_ED25519,
  KIND_WEBAUTHN,
  MAX_ENVELOPE_LEN,
  WEBAUTHN_CHALLENGE_LABEL,
  assembleEnvelope,
  formatWebAuthnES256,
  isValidP256Point,
  memberKeyFromSpki,
  parseDerSignature,
  parseMemberKey,
  verifyMemberSignature,
  verifyWebAuthnEnvelope,
  webAuthnChallenge,
} from './memberkey.js';
export { canonicalScopeList, isCanonicalScopeList, isValidScope } from './scope.js';
export {
  DELEGATION_DOMAIN,
  DELEGATION_MAX_TTL_SECONDS,
  DELEGATION_TYP,
  assembleDelegationWebAuthn,
  delegationBody,
  delegationChallenge,
  newJti,
  parseDelegationBody,
} from './delegation.js';
export {
  APPROVE_TUPLE_PREFIX,
  DOMAIN_APPROVAL_ACTION,
  DOMAIN_APPROVAL_CHALLENGE,
  DOMAIN_APPROVAL_FETCH,
  MATCH_NUMBER_BOUND,
  MAX_APPROVAL_TTL_SECONDS,
  actionDigest,
  approvalAssertion,
  challengePreimage,
  checkAction,
  decodeCanonical,
  encodeApprove,
  fetchPasskeyChallenge,
  fetchPreimage,
  fetchRequest,
  openFetchResponse,
  parseApprove,
  parseFetchNonce,
  parseHandle,
  passkeyChallenge,
} from './approval.js';
export {
  DOMAIN_ENROL_PROOF,
  ENROL_PROOF_MAX_TTL_SECONDS,
  ENROL_PROOF_NONCE_LEN,
  MANAGED_PREFIX,
  checkEnrolProof,
  enrolProofChallenge,
  enrolProofPreimage,
  isEnrollableKey,
  isManagedId,
  verifyEnrolProof,
} from './enrolproof.js';
export { createPasskey, getPasskeyAssertion, registrationOptions } from './browser.js';
export {
  ENROL_PATHS,
  enrolWithInvite,
  httpEnrolTransport,
  parseEnrolInvite,
  parseEnrolNonce,
} from './enrol.js';
