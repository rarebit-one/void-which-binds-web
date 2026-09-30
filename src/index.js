// @rarebit-one/void-which-binds-web — the browser Void-Which-Binds web-login client.
//
// A dependency-light, framework-agnostic ESM module that speaks the ADR-0006
// `weblogin.Broker` wire contract: a browser starts a login, shows a
// `voidbind:login?rp=<origin>&id=<login-id>` QR, an enrolled device (the
// voidbind-kmp phone app, or the `void-which-binds login-approve` CLI stand-in) scans
// and approves, and the browser polls until it holds a short-lived session
// token. The token is carried as `Authorization: Bearer <token>` on fetch and
// as `?token=<token>` on the SSE/EventSource URL (which cannot set a header).
//
// RP-agnostic by construction: `baseUrl` is injected, so the SAME module serves
// the allthing broker and the heyarr broker with no per-RP code. This is a tidy
// extraction of allthing's hand-rolled web/signin.html + web/app.js logic,
// generalised for the two Tizen `.wgt` surfaces (allthing-tizen, heyarr-tizen)
// and browser web clients.
//
// Wire contract (void-which-binds-go `weblogin/handler.go` — the source of truth):
//   POST {baseUrl}/login                   -> { id, qr }
//   POST {baseUrl}/login?mode=number-match -> { id, qr, match_number }   (void-which-binds-go ADR-0006 v2)
//   GET  {baseUrl}/login/{id}              -> { status: 'pending'|'approved'|'expired',
//                                               token?, user? }   (404 once unknown)
// On `approved` the response carries `token` (the session token) and `user`.
// The broker sends no expiry timestamp on create; `status: 'expired'` on the
// poll is the only expiry signal.

'use strict';

import qrcode from './vendor/qrcode.js';

// Default poll cadence, matching allthing's signin.html (1s). The broker is the
// authority on expiry — it returns `status: 'expired'` once its ChallengeTTL
// (ADR-0006) lapses — so the client polls at this interval until the broker
// reports a terminal state rather than timing out on its own clock.
export const POLL_INTERVAL_MS = 1000;

// --- low-level helpers ------------------------------------------------------

// Join an injected base URL with a broker path. A trailing slash on baseUrl is
// trimmed and a leading slash on the path is ensured, so callers may pass
// `https://rp.example` or `https://rp.example/` interchangeably.
export function joinUrl(baseUrl, path) {
  const b = String(baseUrl == null ? '' : baseUrl).replace(/\/+$/, '');
  const p = String(path).charAt(0) === '/' ? String(path) : '/' + String(path);
  return b + p;
}

function makeAbortError() {
  const e = new Error('voidbind web login aborted');
  e.name = 'AbortError';
  return e;
}

// A cancellable delay. Rejects with an AbortError if `signal` fires (or is
// already aborted), so a poll loop unwinds promptly on cancellation.
function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(makeAbortError());
      return;
    }
    const t = setTimeout(() => {
      if (signal) signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    function onAbort() {
      clearTimeout(t);
      reject(makeAbortError());
    }
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
  });
}

// --- QR rendering -----------------------------------------------------------

// Encode a Void-Which-Binds login payload as a scannable QR and return the SVG markup.
// Type 0 auto-picks the smallest version that fits; level 'M' tolerates ~15%
// damage, ample for an on-screen code. The SVG is scalable (no fixed px) and
// carries a white quiet zone so a phone camera reads it in either colour scheme.
export function qrSvg(payload, opts = {}) {
  const ecLevel = opts.ecLevel || 'M';
  const margin = opts.margin == null ? 2 : opts.margin;
  const qr = qrcode(0, ecLevel);
  qr.addData(String(payload));
  qr.make();
  return qr.createSvgTag({ scalable: true, margin });
}

// Render the QR for `qrPayload` into DOM element `el`. Framework-free: `el` is
// any node with `innerHTML` (and optionally `setAttribute`/`classList`). Returns
// true on success, false if rendering failed (caller should fall back to showing
// the login link text). Mirrors allthing signin.html's renderQR.
export function renderQr(el, qrPayload, opts = {}) {
  if (!el) return false;
  try {
    el.innerHTML = qrSvg(qrPayload, opts);
    if (typeof el.setAttribute === 'function') {
      el.setAttribute('role', 'img');
      el.setAttribute('aria-label', 'Voidbind login QR code');
    }
    if (el.classList && typeof el.classList.remove === 'function') {
      el.classList.remove('spin');
    }
    return true;
  } catch (_) {
    return false;
  }
}

// --- token-carrying helpers -------------------------------------------------

// Build a `fetch` wrapper that attaches `Authorization: Bearer <token>` to every
// request — the header path for JSON/REST calls to protected broker routes. An
// empty/absent token yields a passthrough (useful for a loopback dev server with
// auth disabled). `fetchImpl` is injectable for testing; it defaults to the
// ambient global `fetch` (present in browsers, Tizen webviews, and Node 18+).
export function authFetch(token, fetchImpl) {
  const doFetch = fetchImpl || globalThis.fetch;
  return function (input, init = {}) {
    const headers = Object.assign({}, init.headers);
    if (token) headers.Authorization = 'Bearer ' + token;
    return doFetch(input, Object.assign({}, init, { headers }));
  };
}

// Build the URL for an SSE / EventSource stream, appending `?token=<token>`.
// Native EventSource cannot set an Authorization header, so the broker accepts a
// query-param token for the live route only; a short-lived per-login session
// token is a fine query token because it is already rotated every login (the
// exact leak mitigation ADR-0006 relies on). Mirrors app.js withSSEToken.
export function sseUrl(baseUrl, path, token) {
  const url = joinUrl(baseUrl, path);
  if (!token) return url;
  const sep = url.indexOf('?') === -1 ? '?' : '&';
  return url + sep + 'token=' + encodeURIComponent(token);
}

// --- login flow -------------------------------------------------------------

// Start a web login: POST {baseUrl}/login. Resolves with the login id and the
// QR payload (the `voidbind:login?rp=&id=` tuple to render/scan).
//
// `numberMatch: true` requests a void-which-binds-go ADR-0006 v2 number-matching login
// (`POST /login?mode=number-match`). The broker then also returns the true match
// number, surfaced as `matchNumber` (an integer in [0, 100)): the caller MUST
// display it on this screen, because the phone shows only a candidate set and
// the user approves by tapping the number they see here. The QR is identical
// either way. A broker that ignores the mode sends no `match_number`, so
// `matchNumber` is then `undefined` and the login proceeds as a plain v1 QR login.
// `fetchImpl` is injectable for tests.
export async function startWebLogin({ baseUrl, numberMatch = false, signal, fetchImpl } = {}) {
  const doFetch = fetchImpl || globalThis.fetch;
  const path = numberMatch ? '/login?mode=number-match' : '/login';
  const res = await doFetch(joinUrl(baseUrl, path), { method: 'POST', signal });
  if (!res.ok) throw new Error('voidbind login start failed: HTTP ' + res.status);
  const body = await res.json();
  const out = { loginId: body.id, qrPayload: body.qr };
  if (typeof body.match_number === 'number') out.matchNumber = body.match_number;
  return out;
}

// Poll {baseUrl}/login/{loginId} until the device approves. Resolves with
// { token, user } on approval; rejects on expiry, a broker that no longer knows
// the login (non-OK response, e.g. 404), or abort via `signal`. Polls every
// `intervalMs` (default POLL_INTERVAL_MS); the broker's `status` is the
// authority, so this respects the ADR-0006 ChallengeTTL without a local clock.
export async function pollUntilApproved({ baseUrl, loginId, signal, intervalMs = POLL_INTERVAL_MS, fetchImpl } = {}) {
  const doFetch = fetchImpl || globalThis.fetch;
  for (;;) {
    if (signal && signal.aborted) throw makeAbortError();
    const res = await doFetch(joinUrl(baseUrl, '/login/' + encodeURIComponent(loginId)), { signal });
    if (!res.ok) throw new Error('voidbind login no longer exists (HTTP ' + res.status + ')');
    const body = await res.json();
    if (body.status === 'approved') return { token: body.token, user: body.user };
    if (body.status === 'expired') throw new Error('voidbind login expired');
    // void-which-binds-go never sends 'denied' (a refused approval leaves the login
    // pending until it expires), but failing fast on it is harmless should an RP
    // add one.
    if (body.status === 'denied') throw new Error('voidbind login denied');
    // Anything else (e.g. 'pending') — keep waiting.
    await delay(intervalMs, signal);
  }
}

// High-level orchestrator: start a login, render the QR (if `qrElement` given),
// then poll to approval. Resolves with { token, user }. `onStatus`, if given, is
// called with lifecycle updates ({ phase, ... }) so a UI can reflect progress
// without this module owning any DOM. This is the one call a Tizen `.wgt` or a
// web client typically needs; the individual functions above are exposed for
// finer control.
//
// `numberMatch: true` opts into void-which-binds-go ADR-0006 number-matching (see startWebLogin): the
// 'awaiting-approval' update then carries `matchNumber`, which the UI must show
// next to the QR.
export async function signIn({ baseUrl, qrElement, numberMatch = false, signal, onStatus, intervalMs, fetchImpl } = {}) {
  const notify = typeof onStatus === 'function' ? onStatus : () => {};
  notify({ phase: 'starting' });
  const { loginId, qrPayload, matchNumber } = await startWebLogin({ baseUrl, numberMatch, signal, fetchImpl });
  if (qrElement) renderQr(qrElement, qrPayload);
  const awaiting = { phase: 'awaiting-approval', loginId, qrPayload };
  if (matchNumber !== undefined) awaiting.matchNumber = matchNumber;
  notify(awaiting);
  const { token, user } = await pollUntilApproved({ baseUrl, loginId, signal, intervalMs, fetchImpl });
  notify({ phase: 'approved', user });
  return { token, user };
}
