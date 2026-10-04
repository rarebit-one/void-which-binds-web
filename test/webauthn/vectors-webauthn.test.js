// void-which-binds-go's ADR-0018 WebAuthn member-key vectors (test/vectors/webauthn,
// copied verbatim and pinned by VOID_WHICH_BINDS_GO_REF), replayed as Go's
// TestWebAuthnVectorVerdicts replays them: parse the key, derive the challenge
// (a known answer), verify the segment and compare ADR-0018's word. On top,
// every well-formed envelope is re-assembled from its parts and must come out
// byte-identical, which is the browser signer's own output path.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  assembleEnvelope,
  formatWebAuthnES256,
  parseDerSignature,
  parseMemberKey,
  toHex,
  verifyMemberSignature,
  verifyWebAuthnEnvelope,
  webAuthnChallenge,
  VoidWhichBindsError,
} from '../../src/webauthn/index.js';
import { envelopeParts, hex, loadVectors, policyOf, unb64 } from './helpers.js';

const cases = loadVectors('webauthn');
const KNOWN = new Set(['name', 'description', 'key', 'domain', 'body', 'challenge', 'segment', 'policy', 'expect', 'signature_valid']);

test('webauthn: the pinned suite is present', () => {
  assert.equal(cases.length, 41);
});

let reassembled = 0;

for (const { stem, v } of cases) {
  test(`webauthn vector ${stem}: ${v.expect}`, async () => {
    assert.equal(v.name, stem, 'name must equal the file stem');
    for (const k of Object.keys(v)) assert.ok(KNOWN.has(k), `unknown field ${k}`);

    let key;
    try {
      key = parseMemberKey(v.key);
    } catch (e) {
      assert.ok(e instanceof VoidWhichBindsError);
      assert.equal(v.segment, undefined, `ParseMemberKey refused a key that has a segment: ${e.message}`);
      assert.equal(v.expect, 'malformed');
      assert.equal(e.reason, 'malformed');
      return;
    }
    assert.ok(v.segment, 'a key-string case parsed');
    // The canonical rendering round-trips (FormatWebAuthnES256 / String()).
    if (key.kind === 'webauthn') assert.equal(formatWebAuthnES256(key.point), v.key);

    const seg = unb64(v.segment);
    const pol = policyOf(v.policy?.rps, v.policy?.allow_synced);
    let got;
    if (v.domain !== undefined) {
      const body = hex(v.body);
      if (key.kind === 'webauthn') {
        assert.equal(toHex(await webAuthnChallenge(v.domain, body)), v.challenge, 'WebAuthnChallenge known answer');
      }
      got = await verifyMemberSignature(v.key, v.domain, body, seg, pol);
    } else {
      got = await verifyWebAuthnEnvelope(v.key, hex(v.challenge), seg, pol);
    }
    assert.equal(got, v.expect);

    if (v.signature_valid) {
      const parts = envelopeParts(seg);
      const rs = parseDerSignature(parts.signature);
      const k = await crypto.subtle.importKey('raw', key.point, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const h = new Uint8Array(await crypto.subtle.digest('SHA-256', parts.clientDataJSON));
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, rs, Uint8Array.of(...parts.authenticatorData, ...h));
      assert.ok(ok, 'signature_valid: ES256 over authData ‖ SHA-256(clientDataJSON)');
    }

    // Envelope assembly: the parts of every well-formed envelope re-assemble to
    // the exact segment bytes; a non-DER signature is refused at assembly.
    const parts = key.kind === 'webauthn' && !stem.startsWith('envelope-') ? envelopeParts(seg) : null;
    if (parts) {
      if (!parseDerSignature(parts.signature)) {
        assert.throws(() => assembleEnvelope(parts), (e) => e instanceof VoidWhichBindsError && e.reason === 'malformed');
        assert.equal(v.expect, 'bad_signature');
      } else {
        assert.deepEqual(assembleEnvelope(parts), seg, 'assembleEnvelope reproduces the envelope bytes');
        reassembled++;
      }
    }
  });
}

test('webauthn: envelopes re-assembled byte for byte', () => {
  // Every webauthn-key case with a parseable, DER-signed envelope (all but
  // the envelope-* malformations, the two non-DER cases and the bare-signature case).
  assert.equal(reassembled, 26);
});
