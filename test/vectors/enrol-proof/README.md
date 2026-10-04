# Enrol-proof golden vectors

Cross-implementation vectors for the **enrolment proof of possession**
(ADR-0018, amended 2026-10-04, "Enrolment proof"): the proof's framed preimage
and its ADR-0018 WebAuthn challenge under `void-which-binds/roster/enrol-proof/v1`,
proofs by a `webauthn:` or `ed25519:` candidate key, and the verdicts of
`roster.VerifyEnrolProof` and of `identity.MemberKey.VerifyBody` when a proof is
replayed under another domain (or another domain's signature is presented as a
proof). void-which-binds-go generates them
(`go test ./roster -run TestEnrolProofVectors -update`) and replays every file;
void-which-binds-web and void-which-binds-kmp copy them verbatim.

These are stateless cases. The broker's single-use rules (a nonce issued for
this invite and this key, one live nonce per invite, consumed with the invite
on the first proof that verifies) are moneta's and are tested there.

## Layout

One file per case, `<case>.json`. Every key is a **test-only** deterministic
seed or scalar.

```jsonc
{
  "name": "ok-webauthn",                 // == file stem
  "description": "…",
  "webauthn_rps": [ { "rp_id": "broker.example", "origins": [ "https://broker.example" ] } ],
  "keys": {
    "org": { "sign_seed": "<hex>", "id": "ed25519:<hex>" },
    "W":   { "p256_scalar": "<hex>", "synced": false, "id": "webauthn:es256:<130 hex>" }
  },
  "proof": {                             // EnrolProof.Preimage over the fields
    "audience": "https://broker.example", "org": "ed25519:<hex>",
    "mem": "mp:<32 hex>", "key": "<candidate member key>", "nonce": "<64 hex>",
    "issued_at": 1791115200, "expires_at": 1791115320,
    "preimage": "<hex>",                 // with "error": the plain framing Preimage refuses
    "webauthn_challenge": "<hex>",       // webauthn: keys only
    "error": "malformed"                 // optional
  },
  "mints": [                             // every signature the case made
    { "label": "pop", "kind": "webauthn", "signer": "W", "domain": "…", "body": "<hex>",
      "sig": "<b64url of the {ad,cd,sig} envelope>" },
    { "label": "pop", "kind": "ed25519", "signer": "D", "body": "<hex>", "sig": "<b64url>" }
  ],
  "checks": [
    { "label": "verify", "verify": "enrol_proof", "mint": "pop",
      "allow_synced": false, "now": 1791115230, "expect": "ok" },
    { "label": "as-approval", "verify": "raw", "mint": "pop", "key": "W",
      "domain": "void-which-binds/approval/challenge/v1", "body": "<hex>",
      "allow_synced": false, "expect": "challenge_mismatch" }
  ]
}
```

## Replaying

- Re-derive every key id from its seed or scalar.
- Rebuild the preimage from `proof`'s fields:
  `frame(domain) ‖ frame(audience) ‖ frame(org) ‖ frame(mem) ‖ frame(key) ‖
  frame(nonce) ‖ frame(u64be(issued_at)) ‖ frame(u64be(expires_at))`, with
  `frame(p) = u64be(len(p)) ‖ p` and the nonce as its raw 32 bytes. It must
  match byte for byte. For a `webauthn:` key, `webauthn_challenge` is
  `SHA-256("void-which-binds/webauthn/challenge/v1" ‖ 0x00 ‖ domain ‖ 0x00 ‖ preimage)`.
  A proof with `error` must be refused by your preimage function (an empty
  audience, an org that is not a canonical `ed25519:` key, a `mem` that is not
  `mp:<32 hex>`, a key that may not be enrolled, an all-zero nonce,
  `expires_at ≤ issued_at`, or a window over 120 s).
- Re-sign every `ed25519` mint from its seed over `body`: the signature must be
  identical. `webauthn` mints are verify-only, as in `webauthn/`.
- `enrol_proof` checks: the proof is well formed (`malformed`), `now` is in
  `[issued_at, expires_at)` (`expired`), then `VerifyBody` under `proof.key`
  with domain `void-which-binds/roster/enrol-proof/v1` over the preimage, with
  policy `{webauthn_rps, allow_synced}`. A signature refusal is ADR-0018's
  word (`challenge_mismatch`, `wrong_ceremony`, `user_not_verified`,
  `synced_not_allowed`, `bad_signature`, …).
- `raw` checks: `VerifyBody` under `keys[key]` with `domain` over `body`, with
  ADR-0018's word.
