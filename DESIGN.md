# DESIGN — void-which-binds-web

**Status:** Accepted · **Date:** 2026-08-31

A short design record for the `@rarebit-one/void-which-binds-web` package: why it is its
own repo, the wire contract it speaks, and its deliberately narrow scope.

## Why a separate repo

`void-which-binds-web` is the **browser/web protocol-client** for Void-Which-Binds login, split
out of All Thing's in-app `web/signin.html` + `web/app.js`. It gets its own repo
for the same reasons `voidbind-kmp` (the native authenticator) is separate from
`void-which-binds-go` (the server):

- **Consumed by N repos.** The two Tizen `.wgt` surfaces (allthing-tizen,
  heyarr-tizen) and future browser web clients all need the identical
  start → QR → poll → token flow. A shared, versioned package beats copying the
  logic into each surface (which is how it drifted before — allthing had its own
  copy).
- **npm-publishable.** A JS package belongs on the GitHub Packages npm registry
  (`@rarebit-one` scope), so consumers `npm install` a pinned version rather than
  vendoring source.
- **Symmetric peer of `voidbind-kmp`.** The topology is intentionally three
  repos: `void-which-binds-go` (server + wire contract, the source of truth),
  `voidbind-kmp` (native authenticator — the device that approves), and
  `void-which-binds-web` (the browser/web relying-party client). Each RP language surface
  is its own consumer library.
- **Keeps `void-which-binds-go`'s CI clean.** A JS package with a Node test job doesn't
  belong in the Go module's build; separating it keeps each repo's CI single-stack
  (Go stays Go, this stays Node).

## The contract it speaks (ADR-0006)

The module mirrors — does not invent — the `weblogin.Broker` HTTP contract from
[allthing `docs/adr/0006-voidbind-web-login.md`](https://github.com/rarebit-one/allthing/blob/main/docs/adr/0006-voidbind-web-login.md),
as exercised by allthing's `web/signin.html`. The wire shapes themselves are
void-which-binds-go's `weblogin/handler.go` (`createResp`, `pollResp`), the source of truth:

```
POST {baseUrl}/login                   -> { id, qr }
POST {baseUrl}/login?mode=number-match -> { id, qr, match_number }
GET  {baseUrl}/login/{id}              -> { status: 'pending'|'approved'|'expired', token?, user? }
                                          (404 once the broker no longer knows the login)
```

- `qr` is the `voidbind:login?rp=<origin>&id=<login-id>` payload the broker mints
  (byte-identical to void-which-binds-go's `weblogin.EncodeLogin`); the client only
  displays it — it never constructs the tuple.
- On `approved`, the poll response carries the short-lived **session token** and
  the authenticated `user`.
- The token is carried as `Authorization: Bearer <token>` for `fetch` and, for
  the SSE live route whose `EventSource` cannot set a header, as `?token=<token>`.
  A short-lived per-login token is a fine query token: it is already rotated
  every login, which is exactly the leak mitigation the separate-SSE-token rule
  reached for.
- The **broker is the authority on expiry**. It returns `status: 'expired'` once
  its ChallengeTTL (ADR-0006) lapses, so the client polls until a terminal
  status rather than running a local timeout clock. The create response carries
  no expiry timestamp, so there is nothing to count down against.
- **Number-matching (void-which-binds-go ADR-0006 v2) is opt-in** (`numberMatch: true`).
  The create response's `match_number` is the true number. This module surfaces
  it as `matchNumber` for the caller to display, because this browser is the one
  screen the legitimate user is looking at. The phone receives only the
  candidates. Without the option the request carries no `mode`, so existing
  consumers get an unchanged v1 login.

### Where the wire forced a detail

- allthing's `signin.html` uses the wire field names `id` and `qr`. This module
  keeps the wire names on the boundary but exposes them to callers as
  `loginId` / `qrPayload` (and `match_number` as `matchNumber`).
- void-which-binds-go has no `denied` status: a failed approval (wrong number, unknown
  device) leaves the login `pending` so the honest device can still approve, and
  only `expired` ends it. This module still treats a `status: 'denied'` as a
  reject so a non-void-which-binds-go RP that adds one fails fast. Against void-which-binds-go
  that branch never fires.

## Scope

- **QR-only, no push.** ADR-0009 (device push approval) is explicitly out of
  scope: a Tizen `.wgt` is a QR surface. The flow is start → show QR → poll.
- **Framework-free and tiny.** No runtime dependencies, no build step, plain ESM.
  The only bundled code is the vendored `qrcode-generator` (MIT) under
  `src/vendor/` — self-hosted, never a CDN (ADR-0001), so a `.wgt` runs offline.
- **RP-agnostic.** `baseUrl` is injected; no allthing- or heyarr-specific code
  lives here.
- **WebAuthn signer (`./webauthn`, P4–P7 plan milestone W1).** A separate
  subpath, so QR-only consumers never load it. It mirrors void-which-binds-go's
  ADR-0018 member keys and the passkey paths of ADR-0017 (delegation) and
  ADR-0019 (approval and fetch) byte for byte. Golden vectors are copied from
  void-which-binds-go at a pinned commit, and CI diffs them against upstream.
  Pure builders are kept apart from the `navigator.credentials` wrapper so Node
  can test them. WebCrypto only, and no WebAuthn helper library: the wire
  is small and must match Go exactly.
- **Enrolment ceremony (W2).** The same subpath runs the invitee's
  enrolment (below). Its broker wire is proposed until moneta P5 M2.

## Invite and enrolment (P5 W2)

`enrolWithInvite` is the invitee's half of the P4–P7 plan's §3 "Invite and
enrolment" steps 2–3 and of ADR-0018's "Enrolment proof" (amended 2026-10-04,
Proposed). The proof's bytes (`enrolProofPreimage`, `enrolProofChallenge`)
mirror void-which-binds-go `roster.EnrolProof` byte for byte and replay
`enrol-proof/`. The broker's HTTP surface does not exist yet, so the wire
below is a proposal.

> **Proposed, to be fixed by moneta P5 M2.** These paths and bodies are this
> library's proposal, not a contract. moneta's M2 (invite and enrol) fixes
> them, and this section and `httpEnrolTransport` follow. A caller that needs
> a different wire passes `transport: { begin, submitKey, submitProof }` and
> keeps the ceremony.

Every call is a `POST` of JSON to the broker's origin (the PWA's own, so the
RP ID is moneta's host), with `credentials: 'same-origin'` and
`cache: 'no-store'`. The link token rides in the body, never in a URL, so it
stays out of access logs (the link itself should carry it in the fragment,
e.g. `https://<moneta>/i#t=<token>`). Byte fields are unpadded base64url
(canonical); times are whole Unix seconds.

```
POST /enrol/begin  { "invite": <token> }
  200 { "rp": { "id", "name" },
        "user": { "id": b64url(1..64 bytes), "name", "displayName" },
        "challenge": b64url(>= 16 bytes),        registration only; no Go verifier sees it
        "org": "ed25519:<64 hex>", "mem": "mp:<32 hex>" }

POST /enrol/key    { "invite": <token>, "key": "webauthn:es256:<130 hex>" }
  200 { "nonce": b64url(32 bytes), "iat": <s>, "exp": <s> }
                                                 issued against this key; one live nonce per invite

POST /enrol/proof  { "invite": <token>, "key": <the same key>, "sig": b64url(ADR-0018 envelope) }
  200 <opaque JSON, returned to the caller as `result`>

any non-2xx        { "error": "<snake_case word>" }  → VoidWhichBindsError(reason = word, detail = "http_<status>")
```

- **Why `begin`.** The proof binds `org` and `mem`, so the client must know
  them before it can build `B`. ADR-0018 names only `{nonce, iat, exp}` for
  the key response, so they come with the registration options. `user.id` is
  the broker's choice; an opaque per-`mem` handle, not the email, is the
  suggestion.
- **`aud` is the caller's `origin`**, not a broker field: the client binds
  the origin it is running on, and the broker rebuilds `B` from its own
  configured origin. A mismatch fails at the broker as `challenge_mismatch`,
  and already fails the client's pre-flight as `origin_not_allowed`.
- **`/enrol/proof` repeats `key`** so the broker can refuse a proof for a key
  whose nonce a retried `create` already revoked, without reading the
  envelope. It never takes `B` or the window from the request.
- **Fail closed, client side.** No key is posted unless `credProps.rk` is
  `true` (ADR-0018: "`credProps.rk` absent or `false` → no add is submitted").
  The nonce response must build a well-formed proof, so a window over 120 s,
  a zero nonce or a sub-second time is refused before the second ceremony.
  The assertion must come from the credential just created, and it must pass
  `MemberKey.VerifyBody` under the candidate key for `origin` and the
  invite's RP ID. That pre-flight admits synced passkeys (ADR-0018's default
  for an `mp:` person). Whether a synced passkey is admitted, the window and
  single use stay the broker's decision.
- **No hidden network.** `enrolWithInvite` needs an explicit `fetch` (or a
  `transport`) and never falls back to the ambient `fetch`.

## License

AGPL-3.0-or-later, consistent with `voidbind-kmp` and `heyarr-core`. The repo is
private today; the license is written as if public, pending a "make public"
go-ahead.
