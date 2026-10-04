# Action-approval golden vectors (byte layer)

Cross-implementation vectors for the Void-Which-Binds **action-approval
challenge** (ADR-0019, amended 2026-10-03, G9a): the action digest, the
challenge preimage and its ADR-0018 WebAuthn challenge, approval signatures
under an Ed25519 member key or a `webauthn:` passkey, the notify `approve`
tuple, and the authenticated fetch's preimage and proof. void-which-binds-go
generates them (`go test ./approval -run TestApprovalVectors -update`) and
replays every file; void-which-binds-kmp copies them verbatim.

These are the **byte-layer** cases: everything here needs no broker state. The
cases that need the broker (an unknown or already-approved challenge, the
approver's roster standing and authority, nothing written on refusal,
consumption, the fetch nonce store, a wrong approver, a removed person, and the
rate limits) are in `../approval-broker/` (G9b). The approvals' `credential` is
a placeholder that this layer does not judge.

## Layout

One file per case, `<case>.json`. Every key is a **test-only** deterministic
seed. Every section is optional.

```jsonc
{
  "name": "ok-ed25519-device",        // == file stem
  "description": "…",
  "webauthn_rps": [ { "rp_id": "broker.example", "origins": [ "https://broker.example" ] } ],
  "keys": {
    "M.D": { "sign_seed": "<hex>", "id": "ed25519:<hex>" },
    "M.W": { "p256_scalar": "<hex>", "synced": false, "id": "webauthn:es256:<130 hex>" }
  },
  "actions": [                        // Action.Digest over the fields, or Check's refusal
    { "label": "deploy", "kind": "deploy", "resource": "do:team/ops",
      "summary": "…", "params": "<hex>", "digest": "<hex>" }   // or "error": "malformed"
  ],
  "challenges": [                     // Challenge.Preimage over the fields
    { "label": "c", "action": "deploy", "id": "<32 hex>", "nonce": "<hex>",
      "audience": "https://broker.example", "issued_at": 1791028800, "expires_at": 1791028920,
      "match_number": 42, "candidates": [17, 42, 86], "action_digest": "<hex>",
      "resource": "do:team/ops", "ttl": 600,
      "preimage": "<hex>",            // with "error": the hand-framed bytes Preimage refuses
      "webauthn_challenge": "<hex>",  // SHA-256(label ‖ 0 ‖ DomainChallenge ‖ 0 ‖ preimage)
      "error": "malformed",           // optional
      "draw": "<hex>",                // optional: NewChallenge read these bytes to mint it
      "mint_error": "ttl_too_long" }  // optional: NewChallenge refuses these inputs
  ],
  "fetch_preimages": [
    { "label": "fp", "audience": "…", "handle": "<43 b64url>", "nonce": "<43 b64url>",
      "preimage": "<hex>", "webauthn_challenge": "<hex>" }
  ],
  "tuples": [ { "handle": "<43 b64url>", "tuple": "void-which-binds:approve?h=…", "expect": "ok" },
              { "tuple": "<a refused spelling>", "expect": "unknown_handle" } ],
  "mints": [                          // every signature the case made
    { "label": "sig", "kind": "ed25519", "signer": "M.D", "body": "<hex>", "sig": "<b64url>" },
    { "label": "pk",  "kind": "webauthn", "signer": "M.W", "domain": "…", "body": "<hex>",
      "sig": "<b64url of the {ad,cd,sig} envelope>" }
  ],
  "approvals": [                      // CheckAssertion, then VerifyAssertion under keys[approver].id
    { "label": "approve", "challenge": "c", "action": "deploy",
      "assertion": { "credential": "…", "sig": "<b64url>", "match_number": 42 },
      "approver": "M.D", "allow_synced": false, "now": 1791028830, "expect": "ok" }
  ],
  "fetches": [                        // VerifyFetchProof under keys[fetcher].id at audience
    { "label": "fetch", "request": { "handle": "…", "nonce": "…", "credential": "…", "proof": "…" },
      "audience": "https://broker.example", "fetcher": "M.D", "allow_synced": false,
      "nonce_issued_at": 1791028810, "now": 1791028820, "expect": "ok",
      "response_of": { "challenge": "c", "action": "deploy" },   // optional, with
      "response": { "challenge": { … no match number … }, "action": { … } } }
  ],
  "raw": [                            // identity.VerifyBody of a mint over body, ADR-0018 word
    { "label": "…", "mint": "approval", "key": "M.D", "domain": "", "body": "<hex>", "expect": "bad_signature" }
  ],
  "fetch_refusal": { "status": 404, "body": "{\"error\":\"not_found\"}" }
}
```

## Replaying

- Recompute every digest, preimage, WebAuthn challenge and fetch preimage from
  its fields; they must match byte for byte. A challenge with `error` must be
  refused by your preimage function, and its `preimage` is the plain framing of
  its fields.
- Re-sign every `ed25519` mint from its seed over `body`: the signature must be
  identical. Verify every `webauthn` mint over `identity.WebAuthnChallenge(domain,
  body)` (verify-only, as in `webauthn/`).
- Run each approval: the challenge's window, then the assertion's credential,
  signature and number, then the stored action's digest and resource, then the
  signature over the stored challenge's preimage (which binds the true number)
  under the approver's key, with policy `{webauthn_rps, allow_synced}`.
- Run each fetch: the nonce (canonical unpadded base64url of 32 non-zero bytes,
  inside `[nonce_issued_at, nonce_issued_at + 120 s)`), the handle (the same
  shape), a credential and a proof present, then the proof over the fetch
  preimage for `audience`.
- Words: `ok`, `malformed`, `challenge_expired`, `number_mismatch`,
  `digest_mismatch`, `resource_mismatch`, `bad_assertion` (a bad signature or a
  garbled envelope), ADR-0018's other words for a passkey (`challenge_mismatch`,
  `synced_not_allowed`, …), and for a fetch `unknown_handle`,
  `fetch_nonce_spent`, `fetch_unauthenticated` and `bad_fetch_proof`. A fetch
  word is logged only: on the wire every refusal is `fetch_refusal`.
- A `draw` challenge must also come out of your NewChallenge-equivalent when it
  reads exactly those bytes (a broker port only).
