# void-which-binds-web

`@rarebit-one/void-which-binds-web` — the **browser Void-Which-Binds web-login client**. A
dependency-light, framework-agnostic ESM module that lets a browser (or a Tizen
`.wgt` webview) log in to a Void-Which-Binds relying party by showing a QR that an
enrolled device approves — no password, no third party.

It is a tidy extraction of All Thing's hand-rolled `web/signin.html` +
`web/app.js` login logic, generalised so the **same module serves any RP**:
`baseUrl` is injected, so allthing and heyarr brokers are both spoken with no
per-RP code.

> **Renamed (ADR-0013 R1).** This package was `@rarebit-one/voidbind-web`, in the
> repo `rarebit-one/voidbind-web` (the old URL redirects). R1 renames packaging
> only and changes no runtime string: the `voidbind:login` QR scheme is gen1 wire
> and stays until gen2, and the error messages and the QR's `aria-label` are
> unchanged ([void-which-binds-go ADR-0013](https://github.com/rarebit-one/void-which-binds-go/blob/main/docs/adr/0013-gen2-rename-to-void-which-binds-and-re-genesis.md)).

## The Void-Which-Binds three-repo topology

| Repo | Language | Role |
|------|----------|------|
| [`void-which-binds-go`](https://github.com/rarebit-one/void-which-binds-go)  | Go     | **Server / wire contract** — the `weblogin.Broker`, the source of truth |
| [`voidbind-kmp`](https://github.com/rarebit-one/voidbind-kmp) | Kotlin | **Native authenticator** — the phone app that scans + approves |
| **`void-which-binds-web`** (this repo) | JavaScript | **Browser/web client** — shows the QR, polls, holds the session token |

`void-which-binds-web` is the symmetric web peer of `voidbind-kmp`: where the KMP module
lets native apps consume the Void-Which-Binds login over the wire, this module lets
browsers and Tizen `.wgt` surfaces do the same. Keeping it in its own
npm-publishable repo keeps `void-which-binds-go`'s Go CI clean and lets N consumer repos
(allthing-tizen, heyarr-tizen, web clients) depend on one versioned package
instead of re-implementing the flow.

## The protocol (ADR-0006)

1. The browser `POST`s `{baseUrl}/login`; the broker returns `{ id, qr }`, a login
   id and a `voidbind:login?rp=<origin>&id=<login-id>` QR payload.
2. The page renders that as a QR. An enrolled device (the voidbind-kmp phone app,
   or the `void-which-binds login-approve` CLI stand-in) scans and approves it.
3. The browser polls `GET {baseUrl}/login/{id}` (`{ status, token?, user? }`,
   status `pending` | `approved` | `expired`; 404 once the login is unknown) until
   `status` becomes `approved`, which carries a short-lived **session token**.
   `expired` is the only expiry signal. The broker sends no expiry timestamp.
4. The client carries that token as `Authorization: Bearer <token>` on `fetch`
   and as `?token=<token>` on the SSE/`EventSource` URL (which cannot set a
   header). The per-login token is already rotated every login — exactly the
   leak mitigation that makes a query-param token acceptable for SSE.

Tizen scope is **QR-only** — no push (ADR-0009 push is not used here).

### Number-matching (void-which-binds-go ADR-0006 v2, opt-in)

Pass `numberMatch: true` and the client creates the login with
`POST {baseUrl}/login?mode=number-match`. The broker's create response then also
carries `match_number`, the true number (an integer in `[0, 100)`), exposed as
`matchNumber`. **Show it on the sign-in screen.** The phone gets only a set of
candidates and the user approves by tapping the number they see here, so an
approval is bound to this screen. The QR payload is unchanged. A broker without
v2 ignores the mode, so `matchNumber` is then `undefined` and the login proceeds
as plain QR.

```js
await signIn({
  baseUrl,
  qrElement,
  numberMatch: true,
  onStatus: (s) => {
    if (s.phase === 'awaiting-approval' && s.matchNumber !== undefined) {
      matchEl.textContent = String(s.matchNumber).padStart(2, '0');
    }
  },
});
```

## WebAuthn passkey signer (`./webauthn`, ADR-0018)

`@rarebit-one/void-which-binds-web/webauthn` lets a browser sign with an
ADR-0018 passkey member key (`webauthn:es256:<130 hex>`). It covers ADR-0017
delegations to an agent, ADR-0019 action approvals and the approval inbox's
authenticated fetch. It is the client half of void-which-binds-go's
`identity`, `delegation` and `approval` packages, byte for byte. It uses
WebCrypto only and has no runtime dependencies. The pure builders run in Node;
only `getPasskeyAssertion` and `createPasskey` touch `navigator.credentials`.

```js
import {
  delegationBody, delegationChallenge, assembleDelegationWebAuthn,
  getPasskeyAssertion, createPasskey,
} from '@rarebit-one/void-which-binds-web/webauthn';

// Enrolment: a discoverable ES256 passkey with UV. Its member key is what moneta enrols.
const { memberKey, credentialId, backupEligible } = await createPasskey({ rp, user, challenge });

// Delegate to an agent (Go: Delegation.Body -> Challenge -> AssembleWebAuthn).
const body = delegationBody({ usr, org, iss: memberKey, prn, aud, scp, jti, non, iat, exp });
const { envelope } = await getPasskeyAssertion({
  rpId: 'moneta.example', challenge: await delegationChallenge(body), allowCredentials: [credentialId],
});
const token = assembleDelegationWebAuthn(body, envelope);
```

Approvals follow the inbox flow: `parseApprove(tuple)`, then
`fetchPasskeyChallenge(audience, handle, nonce)` and `fetchRequest(...)`, then
`openFetchResponse(json)`. The person taps a number, and then
`passkeyChallenge(challenge, action, chosen)` and
`approvalAssertion(credential, chosen, envelope)`. `openFetchResponse` and
`passkeyChallenge` refuse an action that doesn't recompute to the challenge's
digest. That way the approver signs only what it displayed.

| Export | Mirrors (void-which-binds-go v0.22.0) |
|--------|----------------------------------------|
| `webAuthnChallenge(domain, body)` | `identity.WebAuthnChallenge` |
| `assembleEnvelope({authenticatorData, clientDataJSON, signature})` | the ADR-0018 envelope `{"ad","cd","sig"}` Go verifies |
| `memberKeyFromSpki(spki)` / `formatWebAuthnES256(point)` / `parseMemberKey(s)` | `identity.FormatWebAuthnES256` / `ParseMemberKey` (crypto/ecdh point rule) |
| `verifyMemberSignature(key, domain, body, sig, policy)` / `verifyWebAuthnEnvelope` | `MemberKey.VerifyBody` + `MemberKeyReason` (a client-side pre-flight; the broker is the authority) |
| `delegationBody` / `delegationChallenge` / `assembleDelegationWebAuthn` / `parseDelegationBody` | `Delegation.Body` / `delegation.Challenge` / `AssembleWebAuthn` / `parseBody` |
| `actionDigest` / `challengePreimage` / `passkeyChallenge` / `approvalAssertion` | `Action.Digest` / `Challenge.Preimage` / `PasskeyChallenge` / `WebAuthnAssertion` |
| `fetchPreimage` / `fetchPasskeyChallenge` / `fetchRequest` / `openFetchResponse` | `FetchPreimage` / `FetchPasskeyChallenge` / `FetchRequest` / `FetchResponse.Open` |
| `parseApprove` / `encodeApprove` / `parseHandle` / `parseFetchNonce` | the same names |
| `getPasskeyAssertion` / `createPasskey` | the browser ceremony (UV `required`, ES256 only, `attestation: 'none'`) |

Refusals throw `VoidWhichBindsError` whose `reason` is Go's word (`malformed`,
`wrong_type`, `incomplete`, `issuer_mismatch`, `action_mismatch` with `detail`
`digest_mismatch`/`resource_mismatch`, `unknown_handle`, …).

The browser needs a secure context and WebCrypto. In Node, the pure functions
need Node 19 or later, for global `crypto.subtle` and Ed25519. Registration
needs `AuthenticatorAttestationResponse.getPublicKey()`. No CBOR is parsed, and
a browser without that method is refused.

**Not covered:**
- Roster cosigs by passkey. In void-which-binds-go v0.22.0 a `webauthn:` roster
  key is live but inert (ADR-0014). Only an Ed25519 key signs roster ops and
  cosigs, so there is no passkey challenge to mirror yet.
- The pre-enrolment proof of possession. Its ADR-0018 domain is not registered
  yet.

### Golden vectors

`test/vectors/{webauthn,delegation,approval,scope}/` are verbatim copies of
void-which-binds-go's `testvectors/vectors/`. They are copied at the commit
pinned in `test/vectors/VOID_WHICH_BINDS_GO_REF` (v0.22.0). The suite replays
them byte for byte: challenges, preimages, digests, bodies, envelopes, tokens,
key renderings and refusal words.

`npm run check:vectors` (CI job `vector-drift`) diffs the copies against
upstream at the pin. It reads the private repo with `VOID_WHICH_BINDS_GO_TOKEN`
(the org `AUTOLAND_PAT` in CI). Never hand-edit a vector. Instead, re-copy the
directories and bump the pin in the same change.

## Install

From the GitHub Packages npm registry (scope `@rarebit-one`):

```
# .npmrc
@rarebit-one:registry=https://npm.pkg.github.com
```

```
npm install @rarebit-one/void-which-binds-web
```

> Note: publishing to GitHub Packages for this org is currently **HTTP 402
> (billing)**-blocked (the same block voidbind-kmp hits). The `publish` workflow
> is ready to `workflow_dispatch` once billing is resolved.

## Usage (a Tizen `.wgt` or web client)

```js
import { signIn, authFetch, sseUrl } from '@rarebit-one/void-which-binds-web';

const baseUrl = 'https://allthing.example';      // the RP's Void-Which-Binds broker
const qrElement = document.getElementById('qr');  // any node with innerHTML

// Full flow: POST /login -> render QR -> poll until the device approves.
const { token, user } = await signIn({
  baseUrl,
  qrElement,
  onStatus: (s) => console.log('void-which-binds:', s.phase),
});

// Carry the session token on protected calls.
const api = authFetch(token);
const features = await api(`${baseUrl}/api/features/flights`).then((r) => r.json());

// SSE can't set a header, so the token rides as ?token=.
const live = new EventSource(sseUrl(baseUrl, '/api/live/flights', token));
```

Need finer control? The orchestrator is just the sum of the exported parts:

```js
import { startWebLogin, renderQr, pollUntilApproved } from '@rarebit-one/void-which-binds-web';

const { loginId, qrPayload } = await startWebLogin({ baseUrl });
renderQr(qrElement, qrPayload);
const { token, user } = await pollUntilApproved({ baseUrl, loginId, signal });
```

## API

| Export | Signature | Returns |
|--------|-----------|---------|
| `signIn` | `signIn({ baseUrl, qrElement?, numberMatch?, signal?, onStatus?, intervalMs?, fetchImpl? })` | `Promise<{ token, user }>` (`onStatus` gets `matchNumber` on `awaiting-approval` when number-matching) |
| `startWebLogin` | `startWebLogin({ baseUrl, numberMatch?, signal?, fetchImpl? })` | `Promise<{ loginId, qrPayload, matchNumber? }>` |
| `pollUntilApproved` | `pollUntilApproved({ baseUrl, loginId, signal?, intervalMs?, fetchImpl? })` | `Promise<{ token, user }>` |
| `renderQr` | `renderQr(el, qrPayload, opts?)` | `boolean` (false → show the link text) |
| `qrSvg` | `qrSvg(qrPayload, opts?)` | `string` (SVG markup) |
| `authFetch` | `authFetch(token, fetchImpl?)` | `(input, init?) => Promise<Response>` |
| `sseUrl` | `sseUrl(baseUrl, path, token)` | `string` |
| `joinUrl` | `joinUrl(baseUrl, path)` | `string` |
| `POLL_INTERVAL_MS` | constant | `1000` |

`signal` is an `AbortSignal` — aborting unwinds an in-flight poll promptly.
`fetchImpl` defaults to the ambient global `fetch` (browsers, Tizen webviews,
Node 18+) and is injectable for testing.

## Design

Framework-free and tiny by intent: no runtime dependencies, no build step
(the WebAuthn signer is plain ESM with JSDoc types that `tsc` checks without
emitting). The
QR encoder is the vendored `qrcode-generator` (MIT, Kazuhiko Arase) under
`src/vendor/` — never a CDN, so a `.wgt` runs offline (ADR-0001 self-hosted
policy). See [`DESIGN.md`](./DESIGN.md) for the why-a-separate-repo rationale and
the ADR-0006 contract this module speaks.

## Development

```
npm ci                 # no runtime deps; installs the locked dev tree (typescript)
npm run typecheck      # tsc over the WebAuthn signer's JSDoc types (no emit)
npm test               # node --test — the CI merge gate
npm run check:vectors  # diff test/vectors against void-which-binds-go at the pin
```

## License

[AGPL-3.0-or-later](./LICENSE), matching `voidbind-kmp` and `heyarr-core`.
