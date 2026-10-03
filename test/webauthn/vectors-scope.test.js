// void-which-binds-go's scope vectors (test/vectors/scope): the grammar and the
// canonical list rule a delegation's scp and an action's resource obey.
// intersect.json is the broker's rule and is not replayed here.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { canonicalScopeList, isCanonicalScopeList, isValidScope, VoidWhichBindsError } from '../../src/webauthn/index.js';
import { loadVectors } from './helpers.js';

const v = Object.fromEntries(loadVectors('scope').map((c) => [c.stem, c.v]));

test('scope: valid scopes validate', () => {
  assert.equal(v.valid.scopes.length, 15);
  for (const s of v.valid.scopes) assert.ok(isValidScope(s), s);
});

test('scope: refusals are refused, never normalised', () => {
  assert.ok(v.refusals.cases.length >= 20);
  for (const c of v.refusals.cases) {
    assert.equal(c.expect, 'malformed');
    assert.equal(isValidScope(c.scope), false, `${c.why}: ${JSON.stringify(c.scope)}`);
  }
});

test('scope: lists canonicalise at mint and must already be canonical at verify', () => {
  for (const c of v.lists.cases) {
    if (c.canonical === null) {
      assert.throws(() => canonicalScopeList(c.input), (e) => e instanceof VoidWhichBindsError && e.reason === 'malformed', c.why);
    } else {
      assert.deepEqual(canonicalScopeList(c.input), c.canonical, c.why);
    }
    assert.equal(isCanonicalScopeList(c.input), c.verify === 'ok', c.why);
  }
});
