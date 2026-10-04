// Unit suite for the P5 W2 invite and enrolment ceremony: the EnrolProof field
// refusals the vectors do not spell out, the registration options (credProps,
// discoverable, UV, ES256), and enrolWithInvite end to end against a software
// authenticator and a fake broker speaking the proposed wire (the broker side
// rebuilds the proof from its own records and verifies it, as moneta will).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DOMAIN_ENROL_PROOF,
  ENROL_PATHS,
  b64url,
  checkEnrolProof,
  createPasskey,
  enrolProofPreimage,
  enrolWithInvite,
  httpEnrolTransport,
  memberKeyFromSpki,
  parseEnrolInvite,
  parseEnrolNonce,
  registrationOptions,
  verifyEnrolProof,
  VoidWhichBindsError,
} from '../../src/webauthn/index.js';
import { softAuthenticator } from './helpers.js';

const RP_ID = 'broker.example';
const ORIGIN = 'https://broker.example';
const ORG = 'ed25519:7776e870b93354f2a0b24c23f2a36cc4e80e223218c1b97926fdd018396a2b9b';
const MEM = 'mp:000102030405060708090a0b0c0d0e0f';
const KEY = 'webauthn:es256:04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354';
const NONCE = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
const INVITE_TOKEN = 'link-token-xyz';

const base = () => ({ audience: ORIGIN, org: ORG, mem: MEM, key: KEY, nonce: NONCE, issuedAt: 1791115200, expiresAt: 1791115320 });
const isReason = (r) => (e) => e instanceof VoidWhichBindsError && e.reason === r;

test('enrol proof: field refusals (Go EnrolProof.check)', () => {
  assert.doesNotThrow(() => checkEnrolProof(base()));
  const bad = [
    { audience: '' },
    { org: 'ed25519:' + 'A'.repeat(64) },
    { org: KEY },
    { mem: 'mp:' + '0'.repeat(31) },
    { mem: 'mp:' + 'A'.repeat(32) },
    { mem: ORG },
    { key: 'webauthn:es256:04' + '00'.repeat(64) },
    { key: KEY.toUpperCase() },
    { key: 'x509:abc' },
    { nonce: new Uint8Array(32) },
    { nonce: new Uint8Array(31).fill(1) },
    { issuedAt: 1791115200.5 },
    { issuedAt: new Date(1791115200500) },
    { issuedAt: 0, expiresAt: 60 },
    { expiresAt: 1791115200 },
    { expiresAt: 1791115199 },
    { expiresAt: 1791115321 },
  ];
  for (const b of bad) {
    assert.throws(() => enrolProofPreimage({ ...base(), ...b }), isReason('malformed'), JSON.stringify(b));
  }
  // Whole-second Dates are the same proof as numbers; an ed25519 candidate is enrollable.
  const asDates = { ...base(), issuedAt: new Date(1791115200000), expiresAt: new Date(1791115320000) };
  assert.deepEqual(enrolProofPreimage(asDates), enrolProofPreimage(base()));
  assert.doesNotThrow(() => checkEnrolProof({ ...base(), key: ORG, expiresAt: 1791115201 }));
});

test('enrol proof: verifyEnrolProof is malformed before expired, expired at exp', async () => {
  const pol = { rps: [{ rpId: RP_ID, origins: [ORIGIN] }], allowSynced: false };
  assert.equal(await verifyEnrolProof({ ...base(), mem: ORG }, new Uint8Array(1), pol, 0), 'malformed');
  assert.equal(await verifyEnrolProof(base(), new Uint8Array(1), pol, 1791115320), 'expired');
  assert.equal(await verifyEnrolProof(base(), new Uint8Array(1), pol, 1791115199), 'expired');
  assert.equal(await verifyEnrolProof(base(), new Uint8Array(1), pol, new Date(1791115230000)), 'bad_signature');
});

test('registration: options are discoverable, UV-required, ES256-only, credProps', () => {
  const pk = registrationOptions({
    rp: { id: RP_ID, name: 'Broker' }, user: { id: Uint8Array.of(1), name: 'a@b', displayName: 'A' },
    challenge: new Uint8Array(32), timeout: 60000,
  });
  assert.deepEqual(pk.pubKeyCredParams, [{ type: 'public-key', alg: -7 }]);
  assert.deepEqual(pk.authenticatorSelection, { residentKey: 'required', requireResidentKey: true, userVerification: 'required' });
  assert.equal(pk.attestation, 'none');
  assert.deepEqual(pk.extensions, { credProps: true });
  assert.equal(pk.timeout, 60000);
});

/** softAuthenticator, plus credProps in create()'s extension results. */
async function authenticator({ rk = true, alg = -7, flags, spki } = {}) {
  const sa = await softAuthenticator({ rpId: RP_ID, origin: ORIGIN, flags });
  const create = sa.credentials.create;
  sa.credentials.create = async (opts) => {
    const cred = await create(opts);
    if (rk !== 'no-method') cred.getClientExtensionResults = () => (rk === 'absent' ? {} : { credProps: { rk } });
    if (alg !== -7) cred.response.getPublicKeyAlgorithm = () => alg;
    if (spki) cred.response.getPublicKey = () => spki;
    return cred;
  };
  return sa;
}

test('registration: createPasskey reports credProps.rk as discoverable', async () => {
  const reg = { rp: { id: RP_ID, name: 'B' }, user: { id: Uint8Array.of(1), name: 'n', displayName: 'd' }, challenge: new Uint8Array(32) };
  for (const [rk, want] of [[true, true], [false, false], ['absent', null], ['no-method', null]]) {
    const sa = await authenticator({ rk });
    const out = await createPasskey({ ...reg, credentials: sa.credentials });
    assert.equal(out.discoverable, want, `rk=${rk}`);
    assert.equal(out.memberKey, sa.memberKey);
    assert.deepEqual(sa.calls.create[0].publicKey.extensions, { credProps: true });
  }
});

test('registration: a non-ES256 or non-P-256 credential is refused', async () => {
  const reg = { rp: { id: RP_ID, name: 'B' }, user: { id: Uint8Array.of(1), name: 'n', displayName: 'd' }, challenge: new Uint8Array(32) };
  const rs = await authenticator({ alg: -8 });
  await assert.rejects(createPasskey({ ...reg, credentials: rs.credentials }), isReason('malformed'));
  const p384 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
  const spki = await crypto.subtle.exportKey('spki', p384.publicKey);
  assert.throws(() => memberKeyFromSpki(spki), isReason('malformed'));
  const wrongCurve = await authenticator({ spki });
  await assert.rejects(createPasskey({ ...reg, credentials: wrongCurve.credentials }), isReason('malformed'));
});

/**
 * A fake moneta speaking the proposed wire. It keeps the invite record, issues
 * one live nonce per invite against the posted key, and on the proof rebuilds
 * EnrolProof from its own records and verifies it (Go VerifyEnrolProof).
 */
function fakeBroker({ now = () => Math.floor(Date.now() / 1000), allowSynced = true, tamper = {} } = {}) {
  const calls = [];
  const invite = { token: INVITE_TOKEN, org: ORG, mem: MEM, live: true, issued: null };
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, init, body });
    const reply = (status, json) => ({ ok: status >= 200 && status < 300, status, json: async () => json });
    if (body.invite !== invite.token || !invite.live) return reply(404, { error: 'unknown_invite' });
    if (url === ORIGIN + ENROL_PATHS.begin) {
      return reply(200, {
        rp: { id: RP_ID, name: 'Broker' },
        user: { id: b64url(Uint8Array.of(9, 9, 9)), name: 'invitee@example.com', displayName: 'Invitee' },
        challenge: b64url(new Uint8Array(32).fill(7)),
        org: tamper.org ?? invite.org,
        mem: invite.mem,
      });
    }
    if (url === ORIGIN + ENROL_PATHS.key) {
      const iat = now();
      invite.issued = { key: body.key, nonce: crypto.getRandomValues(new Uint8Array(32)), iat, exp: iat + (tamper.ttl ?? 120) };
      return reply(200, { nonce: b64url(invite.issued.nonce), iat: invite.issued.iat, exp: invite.issued.exp });
    }
    if (url === ORIGIN + ENROL_PATHS.proof) {
      const r = invite.issued;
      if (!r || r.key !== body.key) return reply(409, { error: 'no_live_nonce' });
      const p = { audience: ORIGIN, org: invite.org, mem: invite.mem, key: r.key, nonce: r.nonce, issuedAt: r.iat, expiresAt: r.exp };
      const word = await verifyEnrolProof(p, Uint8Array.from(Buffer.from(body.sig, 'base64url')), {
        rps: [{ rpId: RP_ID, origins: [ORIGIN] }], allowSynced,
      }, now());
      if (word !== 'ok') return reply(400, { error: word });
      invite.live = false;
      return reply(200, { status: 'drafted', mem: invite.mem });
    }
    return reply(404, { error: 'not_found' });
  };
  return { fetch, calls, invite };
}

test('enrolWithInvite: the whole ceremony against a fake broker', async () => {
  const sa = await authenticator();
  const broker = fakeBroker();
  const phases = [];
  const out = await enrolWithInvite({
    origin: ORIGIN, inviteToken: INVITE_TOKEN, fetch: broker.fetch, credentials: sa.credentials,
    onStatus: (s) => phases.push(s.phase),
  });
  assert.deepEqual(phases, ['begin', 'create', 'submit-key', 'assert', 'submit-proof', 'done']);
  assert.equal(out.memberKey, sa.memberKey);
  assert.deepEqual(out.result, { status: 'drafted', mem: MEM });
  assert.equal(out.org, ORG);
  assert.equal(out.mem, MEM);
  assert.equal(broker.invite.live, false);

  // The wire: three POSTs of JSON, the link token in each body, same-origin, uncached.
  assert.deepEqual(broker.calls.map((c) => c.url), [ENROL_PATHS.begin, ENROL_PATHS.key, ENROL_PATHS.proof].map((p) => ORIGIN + p));
  for (const c of broker.calls) {
    assert.equal(c.init.method, 'POST');
    assert.equal(c.init.credentials, 'same-origin');
    assert.equal(c.init.cache, 'no-store');
    assert.equal(c.init.headers['Content-Type'], 'application/json');
    assert.equal(c.body.invite, INVITE_TOKEN);
  }
  assert.deepEqual(Object.keys(broker.calls[1].body), ['invite', 'key']);
  assert.equal(broker.calls[1].body.key, sa.memberKey);
  assert.deepEqual(Object.keys(broker.calls[2].body), ['invite', 'key', 'sig']);
  assert.equal(broker.calls[2].body.sig, b64url(out.envelope));

  // create(): the broker's registration options, discoverable + UV + credProps.
  const created = sa.calls.create[0].publicKey;
  assert.equal(created.rp.id, RP_ID);
  assert.deepEqual(created.user.id, Uint8Array.of(9, 9, 9));
  assert.deepEqual(created.extensions, { credProps: true });
  assert.equal(created.authenticatorSelection.userVerification, 'required');
  // get(): over the enrol-proof challenge, only the new credential, UV required.
  const got = sa.calls.get[0].publicKey;
  assert.equal(got.rpId, RP_ID);
  assert.equal(got.userVerification, 'required');
  assert.equal(got.allowCredentials.length, 1);
  assert.deepEqual(got.allowCredentials[0].id, out.credentialId);
  assert.deepEqual(got.allowCredentials[0].transports, ['internal']);
  const pre = new TextDecoder().decode(out.preimage);
  assert.ok(pre.includes(DOMAIN_ENROL_PROOF) && pre.includes(ORIGIN) && pre.includes(MEM) && pre.includes(sa.memberKey));
});

test('enrolWithInvite: no key is submitted unless credProps.rk is true', async () => {
  for (const rk of [false, 'absent', 'no-method']) {
    const sa = await authenticator({ rk });
    const broker = fakeBroker();
    await assert.rejects(
      enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN, fetch: broker.fetch, credentials: sa.credentials }),
      isReason('not_discoverable'),
    );
    assert.deepEqual(broker.calls.map((c) => c.url), [ORIGIN + ENROL_PATHS.begin], `rk=${rk}`);
    assert.equal(sa.calls.get.length, 0);
  }
});

test('enrolWithInvite: fails closed on a bad nonce response, before asserting', async () => {
  for (const [tamper, why] of [[{ ttl: 121 }, 'window'], [{ ttl: 0 }, 'empty window']]) {
    const sa = await authenticator();
    const broker = fakeBroker({ tamper });
    await assert.rejects(
      enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN, fetch: broker.fetch, credentials: sa.credentials }),
      isReason('malformed'), why,
    );
    assert.equal(sa.calls.get.length, 0, why);
    assert.equal(broker.calls.length, 2, why);
  }
  const sa = await authenticator();
  const broker = fakeBroker({ tamper: { org: 'ed25519:nope' } });
  await assert.rejects(
    enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN, fetch: broker.fetch, credentials: sa.credentials }),
    isReason('malformed'),
  );
  assert.equal(sa.calls.create.length, 0);
});

test('enrolWithInvite: the pre-flight refuses an assertion that would not verify', async () => {
  // UV clear on get(): the browser path still returns an envelope, and the
  // pre-flight stops it before the proof is posted.
  const sa = await authenticator({ flags: 0x01 });
  const broker = fakeBroker();
  await assert.rejects(
    enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN, fetch: broker.fetch, credentials: sa.credentials }),
    isReason('user_not_verified'),
  );
  assert.equal(broker.calls.length, 2);
  // A page origin other than the one the browser reports is origin_not_allowed.
  const other = await authenticator();
  const t = httpEnrolTransport({ fetch: fakeBroker().fetch, baseUrl: ORIGIN });
  await assert.rejects(
    enrolWithInvite({ origin: 'https://evil.example', inviteToken: INVITE_TOKEN, transport: t, credentials: other.credentials }),
    isReason('origin_not_allowed'),
  );
});

test('enrolWithInvite: an assertion from another credential is refused', async () => {
  const sa = await authenticator();
  const get = sa.credentials.get;
  sa.credentials.get = async (opts) => ({ ...(await get(opts)), rawId: Uint8Array.of(9, 9).buffer });
  const broker = fakeBroker();
  await assert.rejects(
    enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN, fetch: broker.fetch, credentials: sa.credentials }),
    isReason('credential_mismatch'),
  );
  assert.equal(broker.calls.length, 2);
});

test("enrolWithInvite: the broker's refusal word surfaces; a synced passkey is the broker's call", async () => {
  const sa = await authenticator({ flags: 0x05 | 0x08 | 0x10 });
  const broker = fakeBroker({ allowSynced: false });
  await assert.rejects(
    enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN, fetch: broker.fetch, credentials: sa.credentials }),
    (e) => isReason('synced_not_allowed')(e) && e.detail === 'http_400',
  );
  const bad = fakeBroker();
  await assert.rejects(
    enrolWithInvite({ origin: ORIGIN, inviteToken: 'wrong', fetch: bad.fetch, credentials: sa.credentials }),
    (e) => isReason('unknown_invite')(e) && e.detail === 'http_404',
  );
  const opaque = async () => ({ ok: false, status: 500, json: async () => { throw new Error('html'); } });
  await assert.rejects(
    enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN, fetch: opaque, credentials: sa.credentials }),
    (e) => isReason('enrol_refused')(e) && e.detail === 'http_500',
  );
});

test('enrolWithInvite: no ambient network, and a custom transport is used as given', async () => {
  const saved = globalThis.fetch;
  globalThis.fetch = () => assert.fail('the ambient fetch must never be called');
  try {
    await assert.rejects(enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN }), TypeError);
    const sa = await authenticator();
    const broker = fakeBroker();
    const http = httpEnrolTransport({ fetch: broker.fetch, baseUrl: ORIGIN });
    const seen = [];
    const transport = {
      begin: (a) => { seen.push('begin'); return http.begin(a); },
      submitKey: (a) => { seen.push('key'); return http.submitKey(a); },
      submitProof: (a) => { seen.push('proof'); return http.submitProof(a); },
    };
    await enrolWithInvite({ origin: ORIGIN, inviteToken: INVITE_TOKEN, transport, credentials: sa.credentials });
    assert.deepEqual(seen, ['begin', 'key', 'proof']);
  } finally {
    globalThis.fetch = saved;
  }
});

test('enrolWithInvite: origin and token are checked up front', async () => {
  for (const origin of ['', 'https://broker.example/', 'https://broker.example/path', 'broker.example']) {
    await assert.rejects(enrolWithInvite({ origin, inviteToken: INVITE_TOKEN, fetch: async () => assert.fail() }), isReason('malformed'), origin);
  }
  await assert.rejects(enrolWithInvite({ origin: ORIGIN, inviteToken: '', fetch: async () => assert.fail() }), isReason('malformed'));
});

test('wire parsers: invite and nonce responses', () => {
  const inv = {
    rp: { id: RP_ID, name: 'B' }, user: { id: b64url(Uint8Array.of(1)), name: 'n', displayName: 'd' },
    challenge: b64url(new Uint8Array(32).fill(1)), org: ORG, mem: MEM,
  };
  assert.equal(parseEnrolInvite(inv).mem, MEM);
  for (const b of [
    { mem: ORG }, { org: 'x' }, { challenge: b64url(new Uint8Array(15)) }, { challenge: 'AA==' },
    { user: { ...inv.user, id: '' } }, { user: { ...inv.user, id: b64url(new Uint8Array(65)) } }, { rp: { id: '', name: 'B' } },
  ]) {
    assert.throws(() => parseEnrolInvite({ ...inv, ...b }), isReason('malformed'), JSON.stringify(b));
  }
  const n = { nonce: b64url(NONCE), iat: 1, exp: 2 };
  assert.deepEqual(parseEnrolNonce(n).nonce, NONCE);
  for (const b of [{ nonce: b64url(new Uint8Array(31)) }, { iat: 1.5 }, { exp: '2' }, { nonce: b64url(NONCE) + '=' }]) {
    assert.throws(() => parseEnrolNonce({ ...n, ...b }), isReason('malformed'), JSON.stringify(b));
  }
});
