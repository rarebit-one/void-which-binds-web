# Delegation grant golden vectors

Cross-implementation vectors for the Void-Which-Binds **delegation grant**
(ADR-0017, amended by G0 and G8): the `void-which-binds.delegation` token, the
agent's `void-which-binds.delegation-pop` proof, the broker nonce, and
`delegation.Verify` against a broker's own org roster (ADR-0016), role policy
and nonce store, for sovereign and org-managed (`mp:`) issuers, Ed25519 and
`webauthn:` (ADR-0018). void-which-binds-go generates them
(`go test ./delegation -run TestDelegationVectors -update`) and replays every
file; void-which-binds-kmp copies them verbatim.

## Layout

One file per case, `<case>.json`. Every key is a **test-only** deterministic
seed (an Ed25519 `sign_seed`, or a passkey's `p256_scalar`), listed so a
consumer can re-sign and reproduce every token.

```jsonc
{
  "name":         "ok-ed25519-device",           // == file stem
  "description":  "…",
  "org":          "ed25519:<hex>",                // the org this broker serves
  "founding":     "<token>",                      // the founding op pinned beside it
  "audience":     "https://broker.example",       // the broker's aud
  "webauthn_rps": [ { "rp_id": "broker.example", "origins": [ "https://broker.example" ] } ],
  "policy":       { "member": [ "app:read", "app:write" ], … },  // role -> scopes
  "served":       [ "app:export", "app:read", … ],               // scopes the broker serves
  "keys": {
    "M.D": { "sign_seed": "<hex>", "id": "ed25519:<hex>" },
    "N":   { "id": "mp:<32 hex>" },
    "M.W": { "p256_scalar": "<hex>", "id": "webauthn:es256:<130 hex>" }
  },
  "stored": {                                     // the broker's records before the first request
    "roster":  [ "<roster op token>" ],
    "persons": { "ed25519:<usr>": [ "<person op token>" ] }
  },
  "nonces": [ { "nonce": "<43 b64url>", "issued_at": 1791032340 } ],  // issued, all unbound
  "mints": [ … ],                                 // every token the case made (below)
  "requests": [                                   // replayed IN ORDER against one broker
    {
      "label":    "r",
      "verifier": "delegation",                   // or "grant" / "possession" (confusion cases)
      "now":      1791032460,
      "headers":  { "Void-Which-Binds-Delegation": "<token>",
                    "Void-Which-Binds-Delegation-Proof": "<token>",
                    "Void-Which-Binds-Membership": "<op>,<op>" },
      "scope":    "app:read",                     // Request.Scope
      "key":      "M.D",                          // grant/possession only: the key to verify under
      "expect": {
        "verified": { "usr": "…", "iss": "…", "prn": "…", "jti": "…", "role": "member",
                      "person_kind": "sovereign", "effective": [ "app:read", "app:write" ] },
        // or "error": "<reason>"
        "commits": { "persons": { "<usr>": [ "<token>" ] }, "roster": [ … ],
                     "nonces": { "<nonce>": "<jti>" } }   // {} when nothing was written
      }
    }
  ]
}
```

`commits` is exactly what the request wrote: person ops by `usr`, roster ops,
and a nonce newly bound to a jti (re-presenting a bound delegation binds
nothing new). A refused request writes nothing.

## Mints

Each entry of `mints` is one token with the inputs that made it:

| kind         | how it was made | a port must |
|--------------|-----------------|-------------|
| `ed25519`    | `delegation.SignWith` by `signer` over `claims` | re-mint `token` byte for byte (the K5 minter) |
| `webauthn`   | `Body` of `claims`, then `signer`'s software authenticator asserted over `Challenge(body)` | reproduce `body` byte for byte; the assertion is verify-only |
| `proof`      | `delegation.SignProofWith` by `signer` over `delegation` (a token), `aud`, `iat`, `ttl` | re-mint `token` byte for byte |
| `hand-built` | `body` written by hand, signed with `signer`'s bare Ed25519 signature | re-sign `body` (refusal cases only; no minter makes these) |
| `possession` | `enrolment.SignPossession` (a confusion case) | — |
| `grant`      | `grant.SignWith` (a confusion case) | — |

`claims` is `{usr, org, iss, prn, aud, scp, jti, non, iat, exp}`; `scp` is as
the minter was handed it, and the minter sorts and de-duplicates it.

The body is the exact `encoding/json` encoding of the payload, fields in the
order `v, typ, usr, org, iss, prn, aud, scp, jti, non, iat, exp`, with no
whitespace. Go's `encoding/json` escapes `<`, `>` and `&` inside strings as
`\u003c`, `\u003e` and `\u0026` (its default HTML escaping), and a port must
emit the same: an `aud` of `https://b.example/?a=1&b=2` is encoded as
`"https://b.example/?a=1\u0026b=2"` (vector `aud-with-ampersand`). A verifier
refuses any other encoding of the same claims, the literal `&` included, as
`malformed` (ADR-0017, amended G8). The proof body is likewise
`v, typ, dlg, aud, iat, exp`, where `dlg` is unpadded base64url of
sha256(delegation body bytes).

## Reasons

Exactly ADR-0017's words: `malformed`, `wrong_type`, `pop_invalid`,
`unknown_user`, `issuer_not_member`, `issuer_removed`, `principal_is_member`,
`bad_signature`, `audience_mismatch`, `not_yet_valid`, `expired`,
`nonce_invalid`, `nonce_reused`, `scope_denied`, `scope_exceeds_role`. The
`grant` verifier reports `grant.ReasonFor`'s words; the `possession` verifier
reports `wrong_type`.
