// void-which-binds-go's ADR-0018 enrolment-proof vectors (test/vectors/enrol-proof),
// replayed as its README says: re-derive every key id from its seed or scalar,
// rebuild every preimage and WebAuthn challenge byte for byte (and refuse every
// proof marked `error`), re-sign every ed25519 mint, and run every check:
// `enrol_proof` through verifyEnrolProof (Go VerifyEnrolProof +
// EnrolProofReason) and `raw` through verifyMemberSignature (MemberKey.VerifyBody).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createECDH } from 'node:crypto';

import {
  DOMAIN_ENROL_PROOF,
  enrolProofChallenge,
  enrolProofPreimage,
  parseMemberKey,
  toHex,
  verifyEnrolProof,
  verifyMemberSignature,
  webAuthnChallenge,
  VoidWhichBindsError,
} from '../../src/webauthn/index.js';
import { concat, frame, u64be } from '../../src/webauthn/bytes.js';
import { hex, loadVectors, policyOf, unb64, utf8 } from './helpers.js';

const cases = loadVectors('enrol-proof');
const PKCS8_ED25519_PREFIX = hex('302e020100300506032b657004220420');

async function ed25519FromSeed(seed) {
  const key = await crypto.subtle.importKey('pkcs8', concat(PKCS8_ED25519_PREFIX, hex(seed)), { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return { key, id: `ed25519:${toHex(unb64(jwk.x))}` };
}

function p256FromScalar(scalar) {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(scalar, 'hex'));
  return `webauthn:es256:${toHex(new Uint8Array(ecdh.getPublicKey()))}`;
}

function proofOf(p) {
  return {
    audience: p.audience, org: p.org, mem: p.mem, key: p.key, nonce: hex(p.nonce),
    issuedAt: p.issued_at, expiresAt: p.expires_at,
  };
}

/** The plain framing, with none of Preimage's checks (what an `error` proof's preimage is). */
function plainFraming(p) {
  return concat(
    frame(utf8(DOMAIN_ENROL_PROOF)), frame(utf8(p.audience)), frame(utf8(p.org)), frame(utf8(p.mem)),
    frame(utf8(p.key)), frame(hex(p.nonce)), frame(u64be(p.issued_at)), frame(u64be(p.expires_at)),
  );
}

const counts = { keys: 0, preimages: 0, challenges: 0, refused: 0, resigned: 0, enrolChecks: 0, rawChecks: 0 };

test('enrol-proof: the pinned suite is present', () => {
  assert.equal(cases.length, 18);
});

for (const { stem, v } of cases) {
  test(`enrol-proof vector ${stem}`, async () => {
    assert.equal(v.name, stem);
    const signers = {};
    for (const [label, k] of Object.entries(v.keys)) {
      if (k.sign_seed) {
        const ed = await ed25519FromSeed(k.sign_seed);
        assert.equal(ed.id, k.id, `${label}: id from seed`);
        signers[label] = ed.key;
      } else {
        assert.equal(p256FromScalar(k.p256_scalar), k.id, `${label}: id from scalar`);
      }
      assert.equal(parseMemberKey(k.id).text, k.id);
      counts.keys++;
    }

    const p = proofOf(v.proof);
    assert.equal(toHex(plainFraming(v.proof)), v.proof.preimage, 'the preimage is the plain framing of the fields');
    if (v.proof.error) {
      assert.throws(() => enrolProofPreimage(p), (e) => e instanceof VoidWhichBindsError && e.reason === v.proof.error);
      await assert.rejects(enrolProofChallenge(p), (e) => e instanceof VoidWhichBindsError && e.reason === v.proof.error);
      counts.refused++;
    } else {
      const pre = enrolProofPreimage(p);
      assert.equal(toHex(pre), v.proof.preimage, 'preimage');
      counts.preimages++;
      if (v.proof.webauthn_challenge) {
        assert.equal(toHex(await enrolProofChallenge(p)), v.proof.webauthn_challenge, 'challenge');
        assert.equal(toHex(await webAuthnChallenge(DOMAIN_ENROL_PROOF, pre)), v.proof.webauthn_challenge);
        counts.challenges++;
      } else {
        assert.ok(p.key.startsWith('ed25519:'), 'only an ed25519 candidate has no challenge');
      }
    }

    const mints = Object.fromEntries((v.mints || []).map((m) => [m.label, m]));
    for (const m of v.mints || []) {
      if (m.kind !== 'ed25519') continue;
      const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signers[m.signer], hex(m.body)));
      assert.deepEqual(sig, unb64(m.sig), `${m.label}: ed25519 re-sign`);
      counts.resigned++;
    }

    for (const c of v.checks) {
      const sig = c.mint ? unb64(mints[c.mint].sig) : new Uint8Array(0);
      const pol = policyOf(v.webauthn_rps, c.allow_synced);
      let got;
      if (c.verify === 'enrol_proof') {
        got = await verifyEnrolProof(p, sig, pol, c.now);
        counts.enrolChecks++;
      } else {
        assert.equal(c.verify, 'raw');
        got = await verifyMemberSignature(v.keys[c.key].id, c.domain, hex(c.body), sig, pol);
        counts.rawChecks++;
      }
      assert.equal(got, c.expect, `${c.label}`);
    }
  });
}

test('enrol-proof: every kind of case was exercised', () => {
  assert.ok(counts.preimages >= 14, `preimages ${counts.preimages}`);
  assert.ok(counts.challenges >= 13, `challenges ${counts.challenges}`);
  assert.equal(counts.refused, 3);
  assert.ok(counts.resigned >= 3, `resigned ${counts.resigned}`);
  assert.equal(counts.enrolChecks, 18);
  assert.equal(counts.rawChecks, 4);
});
