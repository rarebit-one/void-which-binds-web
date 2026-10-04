// Shared helpers for the WebAuthn signer suites: the pinned vector loader and a
// software ES256 authenticator (WebCrypto) for the navigator.credentials mocks.

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { b64url, b64urlDecodeStrict, fromHex, toHex } from '../../src/webauthn/index.js';

const here = dirname(fileURLToPath(import.meta.url));
export const VECTORS = join(here, '..', 'vectors');

/**
 * Every `<case>.json` under test/vectors/<dir>, sorted, parsed, with its stem.
 * @param {string} dir
 */
export function loadVectors(dir) {
  const d = join(VECTORS, dir);
  return readdirSync(d)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: f, stem: f.slice(0, -5), v: JSON.parse(readFileSync(join(d, f), 'utf8')) }));
}

export function hex(s) {
  const b = fromHex(s);
  if (!b) throw new Error(`not hex: ${s}`);
  return b;
}

export function unb64(s) {
  const b = b64urlDecodeStrict(s);
  if (!b) throw new Error(`not unpadded base64url: ${s}`);
  return b;
}

export function utf8(s) {
  return new TextEncoder().encode(s);
}

export function policyOf(rps, allowSynced) {
  return {
    rps: (rps || []).map((rp) => ({ rpId: rp.rp_id, origins: rp.origins })),
    allowSynced: !!allowSynced,
  };
}

/** Splits a JSON envelope into its decoded {ad, cd, sig}, or null. */
export function envelopeParts(envelope) {
  let o;
  try {
    o = JSON.parse(new TextDecoder().decode(envelope));
  } catch {
    return null;
  }
  if (!o || typeof o !== 'object' || Object.keys(o).length !== 3) return null;
  const ad = typeof o.ad === 'string' && b64urlDecodeStrict(o.ad);
  const cd = typeof o.cd === 'string' && b64urlDecodeStrict(o.cd);
  const sig = typeof o.sig === 'string' && b64urlDecodeStrict(o.sig);
  if (!ad || !cd || !sig) return null;
  return { authenticatorData: ad, clientDataJSON: cd, signature: sig };
}

/** r ‖ s (64 bytes) → minimal DER Ecdsa-Sig-Value, as an authenticator emits. */
export function rawToDer(rs) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.subarray(i);
    if (v[0] & 0x80) v = Uint8Array.of(0, ...v);
    return Uint8Array.of(0x02, v.length, ...v);
  };
  const r = int(rs.subarray(0, 32));
  const s = int(rs.subarray(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

/**
 * A software passkey: P-256 key, and get()/create() that answer like a
 * browser's CredentialsContainer, recording the options they were called with.
 */
export async function softAuthenticator({ rpId, origin, flags = 0x05, credentialId = Uint8Array.of(1, 2, 3, 4) }) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(rpId)));
  const calls = { get: [], create: [] };
  const authData = (f) => Uint8Array.of(...rpIdHash, f, 0, 0, 0, 7);
  const clientData = (type, challenge) =>
    utf8(`{"type":"${type}","challenge":"${b64url(new Uint8Array(challenge))}","origin":"${origin}","crossOrigin":false}`);
  const credentials = {
    async get(opts) {
      calls.get.push(opts);
      const ad = authData(flags);
      const cd = clientData('webauthn.get', opts.publicKey.challenge);
      const h = new Uint8Array(await crypto.subtle.digest('SHA-256', cd));
      const rs = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, Uint8Array.of(...ad, ...h)));
      return {
        type: 'public-key',
        rawId: credentialId.buffer.slice(0),
        response: { authenticatorData: ad.buffer, clientDataJSON: cd.buffer, signature: rawToDer(rs).buffer, userHandle: utf8('user-1').buffer },
      };
    },
    async create(opts) {
      calls.create.push(opts);
      return {
        type: 'public-key',
        rawId: credentialId.buffer.slice(0),
        response: {
          clientDataJSON: clientData('webauthn.create', opts.publicKey.challenge).buffer,
          attestationObject: Uint8Array.of(0xa0).buffer,
          getPublicKey: () => spki.buffer,
          getPublicKeyAlgorithm: () => -7,
          getAuthenticatorData: () => authData(flags | 0x40).buffer,
          getTransports: () => ['internal'],
        },
      };
    },
  };
  return { credentials, calls, spki, point, memberKey: `webauthn:es256:${toHex(point)}` };
}
