// void-which-binds-go's ADR-0017 delegation vectors (test/vectors/delegation),
// replayed for the issuer side a browser owns:
//   - every `ed25519` and `webauthn` mint: delegationBody(claims) reproduces
//     the body byte for byte (Go's encoding/json, HTML escaping included);
//   - every `webauthn` mint: delegationChallenge(body) is what the passkey
//     asserted over (the envelope verifies under ADR-0018), the envelope
//     re-assembles from its parts, and assembleDelegationWebAuthn(body,
//     envelope) reproduces the token;
//   - every delegation a request presents: parseDelegationBody reaches Go's
//     step-1 verdict (wrong_type / malformed, else it parses), and a webauthn
//     one re-assembles to the presented token.
// The broker-state steps (roster, policy, nonce store, proof of possession)
// are the broker's and are not replayed here.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DELEGATION_DOMAIN,
  assembleDelegationWebAuthn,
  assembleEnvelope,
  b64url,
  delegationBody,
  delegationChallenge,
  parseDelegationBody,
  verifyMemberSignature,
  verifyWebAuthnEnvelope,
  VoidWhichBindsError,
} from '../../src/webauthn/index.js';
import { envelopeParts, loadVectors, policyOf, unb64, utf8 } from './helpers.js';

const cases = loadVectors('delegation');

function split(token) {
  const [b, s] = token.split('.');
  return { body: unb64(b), sig: unb64(s) };
}

function verdict(fn) {
  try {
    fn();
    return 'ok';
  } catch (e) {
    if (e instanceof VoidWhichBindsError) return e.reason;
    throw e;
  }
}

const counts = { bodies: 0, webauthnMints: 0, presented: 0, refusedAtParse: 0 };

test('delegation: the pinned suite is present', () => {
  assert.equal(cases.length, 52);
});

for (const { stem, v } of cases) {
  test(`delegation vector ${stem}`, async () => {
    assert.equal(v.name, stem);
    const mintsByToken = new Map(v.mints.map((m) => [m.token, m]));

    for (const m of v.mints) {
      if (m.kind !== 'ed25519' && m.kind !== 'webauthn') continue;
      const body = delegationBody(m.claims);
      const want = m.kind === 'webauthn' ? utf8(m.body) : split(m.token).body;
      assert.deepEqual(body, want, `${m.label}: Body(claims) is byte-exact`);
      counts.bodies++;
      if (m.kind !== 'webauthn') continue;

      const { body: tb, sig: envelope } = split(m.token);
      assert.deepEqual(tb, body);
      // The passkey asserted over Challenge(body): verify it both ways.
      const synced = m.claims.usr.startsWith('mp:');
      const pol = policyOf(v.webauthn_rps, synced);
      const want2 = stem === 'webauthn-synced-sovereign-refused' ? 'synced_not_allowed' : 'ok';
      assert.equal(await verifyWebAuthnEnvelope(m.claims.iss, await delegationChallenge(body), envelope, pol), want2);
      assert.equal(await verifyMemberSignature(m.claims.iss, DELEGATION_DOMAIN, body, envelope, pol), want2);
      // Allowing synced passkeys makes the sovereign case verify: the only defect is BE.
      assert.equal(await verifyMemberSignature(m.claims.iss, DELEGATION_DOMAIN, body, envelope, policyOf(v.webauthn_rps, true)), 'ok');
      assert.deepEqual(assembleEnvelope(envelopeParts(envelope)), envelope, `${m.label}: envelope re-assembles`);
      assert.equal(assembleDelegationWebAuthn(body, envelope), m.token, `${m.label}: AssembleWebAuthn reproduces the token`);
      counts.webauthnMints++;
    }

    for (const r of v.requests) {
      if (r.verifier !== 'delegation') continue;
      const tok = r.headers['Void-Which-Binds-Delegation'];
      if (!tok) continue;
      const { body, sig } = split(tok);
      const err = r.expect.error;
      const want = err === 'malformed' || err === 'wrong_type' ? err : 'ok';
      const got = verdict(() => parseDelegationBody(body));
      // A request can be malformed for a reason after step 1; only a hand-built
      // or foreign-typed delegation is expected to fail the body parse.
      const m = mintsByToken.get(tok);
      if (want !== 'ok' && m && m.kind === 'ed25519') {
        assert.equal(got, 'ok', `${r.label}: a minted body parses`);
      } else {
        assert.equal(got, want, `${r.label}: step-1 verdict`);
        if (got !== 'ok') counts.refusedAtParse++;
      }
      if (got === 'ok') {
        const p = parseDelegationBody(body);
        if (p.iss.startsWith('webauthn:')) assert.equal(assembleDelegationWebAuthn(body, sig), tok);
        else {
          assert.throws(() => assembleDelegationWebAuthn(body, sig), (e) => e.reason === 'issuer_mismatch');
        }
      }
      counts.presented++;
    }
  });
}

test('delegation: Body refuses what Go refuses at mint (hand-built bodies)', () => {
  const byStem = Object.fromEntries(cases.map((c) => [c.stem, c.v]));
  const handBody = (stem, label) => utf8(byStem[stem].mints.find((m) => m.label === label).body);
  // iss is the person's genesis key, or the org key: never a member key.
  for (const stem of ['issuer-is-genesis', 'managed-issuer-is-org-key']) {
    const claims = parseDelegationBody(handBody(stem, 'd'));
    assert.throws(() => delegationBody(claims), (e) => e.reason === 'issuer_mismatch', stem);
  }
  // A hand-built body that is canonical re-renders identically through Body.
  const b = handBody('bad-signature', 'd');
  assert.deepEqual(delegationBody(parseDelegationBody(b)), b);
  // The literal '&' spelling is refused; Go's & spelling is the body.
  assert.equal(verdict(() => parseDelegationBody(handBody('aud-with-ampersand', 'literal'))), 'malformed');
  const d = byStem['aud-with-ampersand'].mints.find((m) => m.label === 'd');
  assert.match(new TextDecoder().decode(delegationBody(d.claims)), /\\u0026/);
});

test('delegation: minting refusals', () => {
  const v = cases.find((c) => c.stem === 'ok-webauthn-issuer').v;
  const claims = v.mints.find((m) => m.kind === 'webauthn').claims;
  const r = (patch) => verdict(() => delegationBody({ ...claims, ...patch }));
  assert.equal(r({}), 'ok');
  assert.equal(r({ aud: '' }), 'incomplete');
  assert.equal(r({ iat: undefined }), 'incomplete');
  assert.equal(r({ exp: claims.iat }), 'incomplete');
  assert.equal(r({ exp: claims.iat + 24 * 3600 + 1 }), 'ttl_too_long');
  assert.equal(r({ prn: claims.iss }), 'principal_is_issuer');
  assert.equal(r({ prn: claims.usr }), 'principal_is_issuer');
  assert.equal(r({ iss: claims.org }), 'issuer_mismatch');
  assert.equal(r({ scp: ['App:read'] }), 'malformed');
  assert.equal(r({ scp: [] }), 'malformed');
  assert.equal(r({ jti: 'short' }), 'malformed');
  assert.equal(r({ iss: claims.iss.toUpperCase() }), 'malformed');
  // Scopes are canonicalised at mint, and a Date is whole seconds.
  const a = delegationBody({ ...claims, scp: ['app:write', 'app:read', 'app:read'] });
  const b = delegationBody({ ...claims, iat: new Date(claims.iat * 1000 + 999), exp: new Date(claims.exp * 1000) });
  assert.deepEqual(a, delegationBody(claims));
  assert.deepEqual(b, delegationBody(claims));
  // AssembleWebAuthn refusals.
  const body = delegationBody(claims);
  assert.throws(() => assembleDelegationWebAuthn(body, new Uint8Array(0)), (e) => e.reason === 'incomplete');
  assert.throws(() => assembleDelegationWebAuthn(utf8('{"typ":"void-which-binds.grant"}'), Uint8Array.of(1)), (e) => e.reason === 'wrong_type');
  assert.throws(() => assembleDelegationWebAuthn(utf8(new TextDecoder().decode(body) + ' '), Uint8Array.of(1)), (e) => e.reason === 'malformed');
  assert.equal(b64url(body), assembleDelegationWebAuthn(body, Uint8Array.of(1)).split('.')[0]);
});

test('delegation: replay counts', () => {
  assert.deepEqual(counts, { bodies: 49, webauthnMints: 5, presented: 64, refusedAtParse: 12 });
});
