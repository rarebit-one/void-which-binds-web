// void-which-binds-go's ADR-0019 action-approval vectors (test/vectors/approval,
// the byte layer), replayed as its README says: recompute every digest,
// preimage, WebAuthn challenge and fetch preimage; verify every mint; run every
// approval and fetch through the store-free checks; parse every tuple; open
// every fetch response. The verdict harness below composes the library's pure
// functions in Go's CheckAssertion / VerifyAssertion / VerifyFetchProof order;
// the broker-state cases are in approval-broker/ (not copied: broker-side).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DOMAIN_APPROVAL_CHALLENGE,
  DOMAIN_APPROVAL_FETCH,
  actionDigest,
  approvalAssertion,
  assembleEnvelope,
  b64url,
  challengePreimage,
  decodeCanonical,
  encodeApprove,
  fetchPasskeyChallenge,
  fetchPreimage,
  fetchRequest,
  openFetchResponse,
  parseApprove,
  parseFetchNonce,
  parseHandle,
  parseMemberKey,
  passkeyChallenge,
  toHex,
  verifyMemberSignature,
  verifyWebAuthnEnvelope,
  webAuthnChallenge,
  VoidWhichBindsError,
} from '../../src/webauthn/index.js';
import { envelopeParts, hex, loadVectors, policyOf, utf8 } from './helpers.js';

const cases = loadVectors('approval');
const MAX_SIG_LEN = 22 << 10;
const FETCH_NONCE_TTL = 120;

function actionOf(a) {
  return { kind: a.kind, resource: a.resource, summary: a.summary, params: hex(a.params) };
}

function challengeOf(c) {
  return {
    id: c.id, nonce: hex(c.nonce), audience: c.audience, issuedAt: c.issued_at, expiresAt: c.expires_at,
    matchNumber: c.match_number, candidates: c.candidates, actionDigest: hex(c.action_digest),
    resource: c.resource, ttl: c.ttl,
  };
}

async function reasonOf(fn) {
  try {
    await fn();
    return 'ok';
  } catch (e) {
    if (e instanceof VoidWhichBindsError) return e.detail ?? e.reason;
    throw e;
  }
}

/** Go verifyMemberSig, mapped by sentinel. */
async function memberSig(domain, body, sig, key, pol) {
  if (!sig || sig.length > MAX_SIG_LEN) return 'bad_signature';
  const raw = decodeCanonical(sig);
  if (!raw) return 'bad_signature';
  return verifyMemberSignature(key, domain, body, raw, pol);
}

/** Go CheckAssertion then VerifyAssertion, with ReasonFor's words. */
async function approve(c, stored, a, now, key, pol) {
  let pre;
  try {
    pre = challengePreimage(c);
  } catch {
    return 'malformed';
  }
  if (!(now < c.expiresAt)) return 'challenge_expired';
  if (!a.credential || !a.sig || a.match_number === undefined || a.match_number === null) return 'malformed';
  if (a.match_number !== c.matchNumber) return 'number_mismatch';
  let d;
  try {
    d = await actionDigest(stored);
  } catch {
    return 'malformed';
  }
  if (toHex(d) !== toHex(c.actionDigest)) return 'digest_mismatch';
  if (stored.resource !== c.resource) return 'resource_mismatch';
  const w = await memberSig(DOMAIN_APPROVAL_CHALLENGE, pre, a.sig, key, pol);
  return w === 'bad_signature' || w === 'malformed' ? 'bad_assertion' : w;
}

/** Go VerifyFetchProof. */
async function fetchVerdict(req, audience, key, pol, issuedAt, now) {
  let n;
  let h;
  try {
    n = parseFetchNonce(req.nonce);
  } catch (e) {
    return e.reason;
  }
  if (now < issuedAt || !(now < issuedAt + FETCH_NONCE_TTL)) return 'fetch_nonce_spent';
  try {
    h = parseHandle(req.handle);
  } catch (e) {
    return e.reason;
  }
  if (!req.credential || !req.proof) return 'fetch_unauthenticated';
  let pre;
  try {
    pre = fetchPreimage(audience, h, n);
  } catch {
    return 'bad_fetch_proof';
  }
  const w = await memberSig(DOMAIN_APPROVAL_FETCH, pre, req.proof, key, pol);
  return w === 'ok' ? 'ok' : 'bad_fetch_proof';
}

const counts = {
  actions: 0, challenges: 0, fetchPreimages: 0, tuples: 0, mints: 0, envelopes: 0,
  approvals: 0, fetches: 0, responses: 0, raw: 0,
};

test('approval: the pinned suite is present', () => {
  assert.equal(cases.length, 28);
});

for (const { stem, v } of cases) {
  test(`approval vector ${stem}`, async () => {
    assert.equal(v.name, stem);
    const keys = v.keys || {};
    const actions = Object.fromEntries((v.actions || []).map((a) => [a.label, a]));
    const challenges = Object.fromEntries((v.challenges || []).map((c) => [c.label, c]));
    const mints = Object.fromEntries((v.mints || []).map((m) => [m.label, m]));

    for (const k of Object.values(keys)) parseMemberKey(k.id);

    for (const a of v.actions || []) {
      const got = await reasonOf(async () => {
        assert.equal(toHex(await actionDigest(actionOf(a))), a.digest, `${a.label}: digest`);
      });
      assert.equal(got, a.error ?? 'ok', `${a.label}: Check`);
      counts.actions++;
    }

    for (const c of v.challenges || []) {
      const ch = challengeOf(c);
      if (c.error) {
        assert.throws(() => challengePreimage(ch), (e) => e.reason === c.error, `${c.label}: refused`);
      } else {
        const pre = challengePreimage(ch);
        assert.equal(toHex(pre), c.preimage, `${c.label}: preimage`);
        assert.equal(toHex(await webAuthnChallenge(DOMAIN_APPROVAL_CHALLENGE, pre)), c.webauthn_challenge);
        // PasskeyChallenge over the fetched action and the true number.
        const a = actions[c.action];
        const want = !a || a.error || a.digest !== c.action_digest ? 'digest_mismatch'
          : a.resource !== c.resource ? 'resource_mismatch' : 'ok';
        const got = await reasonOf(async () => {
          const pk = await passkeyChallenge({ ...ch, matchNumber: 0 }, actionOf(a), c.match_number);
          assert.equal(toHex(pk), c.webauthn_challenge, `${c.label}: PasskeyChallenge`);
        });
        assert.equal(got, want, `${c.label}: PasskeyChallenge verdict`);
      }
      counts.challenges++;
    }

    for (const f of v.fetch_preimages || []) {
      const h = parseHandle(f.handle);
      const n = parseFetchNonce(f.nonce);
      assert.equal(toHex(fetchPreimage(f.audience, h, n)), f.preimage);
      assert.equal(toHex(await fetchPasskeyChallenge(f.audience, h, n)), f.webauthn_challenge);
      counts.fetchPreimages++;
    }

    for (const t of v.tuples || []) {
      const got = await reasonOf(async () => {
        const h = parseApprove(t.tuple);
        assert.equal(b64url(h), t.handle);
        assert.equal(encodeApprove(h), t.tuple);
      });
      assert.equal(got, t.expect, JSON.stringify(t.tuple));
      counts.tuples++;
    }

    for (const m of v.mints || []) {
      const k = keys[m.signer];
      const sig = decodeCanonical(m.sig);
      const pol = policyOf(v.webauthn_rps, k.synced);
      assert.equal(await verifyMemberSignature(k.id, m.domain ?? DOMAIN_APPROVAL_CHALLENGE, hex(m.body), sig, pol), 'ok', `${m.label}: mint verifies`);
      if (m.kind === 'webauthn') {
        assert.deepEqual(assembleEnvelope(envelopeParts(sig)), sig, `${m.label}: envelope re-assembles`);
        counts.envelopes++;
      }
      counts.mints++;
    }

    for (const ap of v.approvals || []) {
      const c = challengeOf(challenges[ap.challenge]);
      const stored = actionOf(actions[ap.action]);
      const k = keys[ap.approver];
      const pol = policyOf(v.webauthn_rps, ap.allow_synced);
      const got = await approve(c, stored, ap.assertion, ap.now, k.id, pol);
      assert.equal(got, ap.expect, `${ap.label}`);
      if (ap.expect === 'ok' && k.id.startsWith('webauthn:')) {
        // The client path: the passkey asserted over PasskeyChallenge(fetched, chosen),
        // and approvalAssertion rebuilds the exact assertion body.
        const env = decodeCanonical(ap.assertion.sig);
        const pk = await passkeyChallenge({ ...c, matchNumber: 0 }, stored, ap.assertion.match_number);
        assert.equal(await verifyWebAuthnEnvelope(k.id, pk, env, pol), 'ok');
        assert.deepEqual(approvalAssertion(ap.assertion.credential, ap.assertion.match_number, env), ap.assertion);
      }
      counts.approvals++;
    }

    for (const f of v.fetches || []) {
      const k = keys[f.fetcher];
      const pol = policyOf(v.webauthn_rps, f.allow_synced);
      const got = await fetchVerdict(f.request, f.audience, k.id, pol, f.nonce_issued_at, f.now);
      assert.equal(got, f.expect, f.label);
      if (f.expect === 'ok' && k.id.startsWith('webauthn:')) {
        const env = decodeCanonical(f.request.proof);
        const pk = await fetchPasskeyChallenge(f.audience, parseHandle(f.request.handle), parseFetchNonce(f.request.nonce));
        assert.equal(await verifyWebAuthnEnvelope(k.id, pk, env, pol), 'ok');
        assert.deepEqual(
          fetchRequest({ handle: f.request.handle, nonce: f.request.nonce, credential: f.request.credential, envelope: env }),
          f.request,
        );
      }
      if (f.response) {
        const { challenge: oc, action: oa } = await openFetchResponse(f.response);
        const want = challenges[f.response_of.challenge];
        assert.equal(oc.matchNumber, 0, 'the approver never learns the number');
        assert.equal(toHex(challengePreimage({ ...oc, matchNumber: want.match_number })), want.preimage);
        assert.equal(toHex(await passkeyChallenge(oc, oa, want.match_number)), want.webauthn_challenge);
        assert.deepEqual(oc.candidates, want.candidates);
        assert.equal(toHex(await actionDigest(oa)), actions[f.response_of.action].digest);
        counts.responses++;
      }
      counts.fetches++;
    }

    for (const r of v.raw || []) {
      const k = keys[r.key];
      const sig = decodeCanonical(mints[r.mint].sig);
      assert.equal(await verifyMemberSignature(k.id, r.domain, hex(r.body), sig, policyOf(v.webauthn_rps, false)), r.expect, r.label);
      counts.raw++;
    }
  });
}

test('approval: refusals on the approver side', async () => {
  const v = cases.find((c) => c.stem === 'fetch-ok-webauthn-approver').v;
  const f = v.fetches[0];
  const { challenge, action } = await openFetchResponse(f.response);
  // The approver signs only what it displayed.
  const r = (p) => reasonOf(() => passkeyChallenge(challenge, { ...action, ...p }, 42));
  assert.equal(await r({ summary: 'Deploy something else' }), 'digest_mismatch');
  assert.equal(await r({ kind: 'Deploy' }), 'malformed');
  assert.equal(await reasonOf(() => passkeyChallenge(challenge, action, 100)), 'malformed');
  assert.equal(await reasonOf(() => passkeyChallenge({ ...challenge, resource: 'do:team/dev' }, action, 42)), 'resource_mismatch');
  // A tampered response is refused before anything is displayed.
  const bad = structuredClone(f.response);
  bad.action.summary = 'Deploy web v2026.10.03.1 to staging';
  assert.equal(await reasonOf(() => openFetchResponse(bad)), 'digest_mismatch');
  const ttl = structuredClone(f.response);
  ttl.challenge.ttl = 3601;
  assert.equal(await reasonOf(() => openFetchResponse(ttl)), 'malformed');
  const cand = structuredClone(f.response);
  cand.challenge.candidates = [17, 17, 86];
  assert.equal(await reasonOf(() => openFetchResponse(cand)), 'malformed');
  assert.throws(() => approvalAssertion('', 1, Uint8Array.of(1)), (e) => e.reason === 'malformed');
  assert.throws(() => fetchPreimage('', new Uint8Array(32).fill(1), new Uint8Array(32).fill(1)), (e) => e.reason === 'malformed');
  assert.throws(() => fetchPreimage('a', new Uint8Array(32), new Uint8Array(32).fill(1)), (e) => e.reason === 'malformed');
  assert.deepEqual(utf8('x'), Uint8Array.of(0x78));
});

test('approval: replay counts', () => {
  assert.deepEqual(counts, {
    actions: 31, challenges: 24, fetchPreimages: 9, tuples: 12, mints: 32, envelopes: 9,
    approvals: 27, fetches: 17, responses: 2, raw: 2,
  });
});
