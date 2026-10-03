// Unit suite for the pieces the vectors cannot reach: registration (SPKI →
// member key) against keys WebCrypto generates, Go's JSON spelling, strict DER,
// and the navigator.credentials wrapper driven end to end by a software
// authenticator (a delegation and an approval minted through the browser path
// and verified under ADR-0018).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DELEGATION_DOMAIN,
  DOMAIN_APPROVAL_FETCH,
  assembleDelegationWebAuthn,
  assembleEnvelope,
  createPasskey,
  delegationBody,
  delegationChallenge,
  fetchPasskeyChallenge,
  formatWebAuthnES256,
  fetchPreimage,
  getPasskeyAssertion,
  memberKeyFromSpki,
  parseDerSignature,
  parseMemberKey,
  toHex,
  verifyMemberSignature,
  VoidWhichBindsError,
} from '../../src/webauthn/index.js';
import { goJsonMarshal, goJsonString } from '../../src/webauthn/json.js';
import { loadVectors, rawToDer, softAuthenticator, unb64, utf8 } from './helpers.js';

const RP = { rpId: 'broker.example', origin: 'https://broker.example' };
const POLICY = { rps: [{ rpId: RP.rpId, origins: [RP.origin] }], allowSynced: false };

test('registration: SPKI from WebCrypto renders as webauthn:es256 and parses back', async () => {
  for (let i = 0; i < 8; i++) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const spki = await crypto.subtle.exportKey('spki', kp.publicKey);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const key = memberKeyFromSpki(spki);
    assert.equal(key, `webauthn:es256:${toHex(raw)}`);
    assert.match(key, /^webauthn:es256:04[0-9a-f]{128}$/);
    assert.equal(parseMemberKey(key).text, key);
    assert.equal(formatWebAuthnES256(raw), key);
  }
});

test('registration: non-P-256 or malformed SPKI is refused', async () => {
  const p384 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
  const ed = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign']);
  const p256 = new Uint8Array(await crypto.subtle.exportKey('spki', (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])).publicKey));
  const offCurve = p256.slice();
  offCurve[offCurve.length - 1] ^= 1;
  for (const spki of [
    await crypto.subtle.exportKey('spki', p384.publicKey),
    await crypto.subtle.exportKey('spki', ed.publicKey),
    p256.subarray(0, 90),
    offCurve,
  ]) {
    assert.throws(() => memberKeyFromSpki(spki), (e) => e instanceof VoidWhichBindsError && e.reason === 'malformed');
  }
});

test('registration: every webauthn vector key re-renders from its point', () => {
  const keys = loadVectors('webauthn').map((c) => c.v.key).filter((k) => k.startsWith('webauthn:'));
  let n = 0;
  for (const k of keys) {
    let mk;
    try {
      mk = parseMemberKey(k);
    } catch {
      continue;
    }
    assert.equal(formatWebAuthnES256(mk.point), k);
    n++;
  }
  assert.ok(n > 20);
});

test("json: Go's encoding/json spelling", () => {
  assert.equal(goJsonString('https://b.example/?a=1&b=<2>'), '"https://b.example/?a=1\\u0026b=\\u003c2\\u003e"');
  assert.equal(goJsonString('  \b\f\n\r\t\u0001"\\/é🚀\u007f'), '"\\u2028\\u2029\\b\\f\\n\\r\\t\\u0001\\"\\\\/é🚀\u007f"');
  assert.equal(goJsonMarshal({ v: 1, scp: ['a:b'], z: null }), '{"v":1,"scp":["a:b"],"z":null}');
  assert.throws(() => goJsonString('\ud800'), (e) => e.reason === 'malformed');
});

test('DER: strict as Go ecdsa.VerifyASN1', () => {
  const rs = new Uint8Array(64);
  rs[31] = 1;
  rs[63] = 2;
  const der = rawToDer(rs);
  assert.deepEqual(parseDerSignature(der), rs);
  assert.equal(parseDerSignature(Uint8Array.of(...der, 0)), null, 'trailing byte');
  assert.equal(parseDerSignature(rs), null, 'raw r ‖ s');
  assert.equal(parseDerSignature(Uint8Array.of(0x30, 6, 2, 1, 0, 2, 1, 1)), null, 'r = 0');
  assert.equal(parseDerSignature(Uint8Array.of(0x30, 7, 2, 2, 0, 1, 2, 1, 1)), null, 'non-minimal INTEGER');
  assert.equal(parseDerSignature(Uint8Array.of(0x30, 0x81, 6, 2, 1, 1, 2, 1, 1)), null, 'long-form short length');
  assert.equal(parseDerSignature(Uint8Array.of(0x30, 6, 2, 1, 0x81, 2, 1, 1)), null, 'negative r');
  assert.throws(() => assembleEnvelope({ authenticatorData: Uint8Array.of(1), clientDataJSON: Uint8Array.of(1), signature: rs }), (e) => e.reason === 'malformed');
});

test('browser: a passkey delegation through navigator.credentials.get verifies and assembles', async () => {
  const auth = await softAuthenticator(RP);
  const claims = {
    usr: 'ed25519:' + '11'.repeat(32), org: 'ed25519:' + '22'.repeat(32), iss: auth.memberKey,
    prn: 'ed25519:' + '33'.repeat(32), aud: RP.origin, scp: ['app:write', 'app:read'],
    jti: 'AAECAwQFBgcICQoLDA0ODw', non: 'oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8',
    iat: 1790000000, exp: 1790003600,
  };
  const body = delegationBody(claims);
  const challenge = await delegationChallenge(body);
  const a = await getPasskeyAssertion({ rpId: RP.rpId, challenge, allowCredentials: [Uint8Array.of(9, 9)], credentials: auth.credentials, timeout: 60000 });
  const opts = auth.calls.get[0].publicKey;
  assert.equal(opts.userVerification, 'required');
  assert.equal(opts.rpId, RP.rpId);
  assert.equal(opts.timeout, 60000);
  assert.deepEqual(opts.allowCredentials, [{ type: 'public-key', id: Uint8Array.of(9, 9) }]);
  assert.deepEqual(new Uint8Array(opts.challenge), challenge);
  assert.deepEqual(a.userHandle, utf8('user-1'));
  assert.equal(await verifyMemberSignature(auth.memberKey, DELEGATION_DOMAIN, body, a.envelope, POLICY), 'ok');
  const token = assembleDelegationWebAuthn(body, a.envelope);
  const [tb, te] = token.split('.');
  assert.deepEqual(unb64(tb), body);
  assert.deepEqual(unb64(te), a.envelope);
});

test('browser: a passkey fetch proof verifies under DomainFetch only', async () => {
  const auth = await softAuthenticator(RP);
  const h = new Uint8Array(32).fill(7);
  const n = new Uint8Array(32).fill(8);
  const a = await getPasskeyAssertion({ rpId: RP.rpId, challenge: await fetchPasskeyChallenge(RP.origin, h, n), credentials: auth.credentials });
  const pre = fetchPreimage(RP.origin, h, n);
  assert.equal(await verifyMemberSignature(auth.memberKey, DOMAIN_APPROVAL_FETCH, pre, a.envelope, POLICY), 'ok');
  assert.equal(await verifyMemberSignature(auth.memberKey, DELEGATION_DOMAIN, pre, a.envelope, POLICY), 'challenge_mismatch');
});

test('browser: a synced passkey is flagged at registration and refused for a sovereign person', async () => {
  const auth = await softAuthenticator({ ...RP, flags: 0x1d });
  const reg = await createPasskey({
    rp: { id: RP.rpId, name: 'Broker' }, user: { id: utf8('u'), name: 'u', displayName: 'U' },
    challenge: new Uint8Array(32), credentials: auth.credentials,
  });
  const opts = auth.calls.create[0].publicKey;
  assert.deepEqual(opts.pubKeyCredParams, [{ type: 'public-key', alg: -7 }]);
  assert.equal(opts.authenticatorSelection.userVerification, 'required');
  assert.equal(opts.authenticatorSelection.residentKey, 'required');
  assert.equal(opts.attestation, 'none');
  assert.equal(reg.memberKey, auth.memberKey);
  assert.equal(reg.backupEligible, true);
  assert.deepEqual(reg.transports, ['internal']);
  const body = utf8('a body');
  const a = await getPasskeyAssertion({ rpId: RP.rpId, challenge: await delegationChallenge(body), credentials: auth.credentials });
  assert.equal(await verifyMemberSignature(reg.memberKey, DELEGATION_DOMAIN, body, a.envelope, POLICY), 'synced_not_allowed');
  assert.equal(await verifyMemberSignature(reg.memberKey, DELEGATION_DOMAIN, body, a.envelope, { ...POLICY, allowSynced: true }), 'ok');
});

test('browser: an assertion over another challenge, or the wrong algorithm, is refused', async () => {
  const auth = await softAuthenticator(RP);
  const lying = { ...auth.credentials, get: (o) => auth.credentials.get({ ...o, publicKey: { ...o.publicKey, challenge: new Uint8Array(32) } }) };
  await assert.rejects(
    getPasskeyAssertion({ rpId: RP.rpId, challenge: new Uint8Array(32).fill(1), credentials: lying }),
    (e) => e instanceof VoidWhichBindsError && e.reason === 'challenge_mismatch',
  );
  await assert.rejects(getPasskeyAssertion({ rpId: RP.rpId, challenge: new Uint8Array(16), credentials: auth.credentials }), (e) => e.reason === 'malformed');
  const rsa = {
    ...auth.credentials,
    create: async (o) => {
      const c = await auth.credentials.create(o);
      return { ...c, response: { ...c.response, getPublicKeyAlgorithm: () => -257 } };
    },
  };
  await assert.rejects(
    createPasskey({ rp: { id: RP.rpId, name: 'B' }, user: { id: utf8('u'), name: 'u', displayName: 'U' }, challenge: new Uint8Array(32), credentials: rsa }),
    (e) => e.reason === 'malformed',
  );
});
