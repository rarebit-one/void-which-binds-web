#!/usr/bin/env bash
# Fails if the golden vectors under test/vectors/ have drifted from
# void-which-binds-go's testvectors/vectors/ at the commit pinned in
# test/vectors/VOID_WHICH_BINDS_GO_REF.
#
# void-which-binds-go is the single source of truth for Void-Which-Binds protocol
# vectors (its `testvectors` package); this repo carries a verbatim copy of the
# directories the WebAuthn signer replays (webauthn/, delegation/, approval/,
# scope/, enrol-proof/). Each copied directory must equal upstream's byte for
# byte, README included; directories this repo does not use are not copied.
# Never edit a copied vector here: re-copy it from void-which-binds-go and bump
# the pin in the same change. (Mirrors void-which-binds-kmp's scripts/check-vector-drift.sh.)
#
# Env:
#   VOID_WHICH_BINDS_GO_TOKEN  token that can read the (private) void-which-binds-go
#                              repo over HTTPS; optional when git already has
#                              credentials.
#   VOID_WHICH_BINDS_GO_URL    clone URL or local path (default: the GitHub repo).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
vectors="$root/test/vectors"
pin_file="$vectors/VOID_WHICH_BINDS_GO_REF"
url="${VOID_WHICH_BINDS_GO_URL:-https://github.com/rarebit-one/void-which-binds-go.git}"

ref="$(sed -e 's/#.*//' "$pin_file" | tr -d '[:space:]')"
if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error file=test/vectors/VOID_WHICH_BINDS_GO_REF::expected a full 40-char void-which-binds-go commit SHA, got '$ref'" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

auth=()
if [[ -n "${VOID_WHICH_BINDS_GO_TOKEN:-}" ]]; then
  basic="$(printf 'x-access-token:%s' "$VOID_WHICH_BINDS_GO_TOKEN" | base64 | tr -d '\n')"
  auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $basic")
fi

git -C "$work" init -q
git ${auth[@]+"${auth[@]}"} -C "$work" fetch -q --depth 1 "$url" "$ref"
git -C "$work" checkout -q FETCH_HEAD -- testvectors/vectors
upstream="$work/testvectors/vectors"

status=0
# Only the pin file may sit beside the copied directories.
for entry in "$vectors"/*; do
  name="$(basename "$entry")"
  [[ "$name" == "VOID_WHICH_BINDS_GO_REF" ]] && continue
  if [[ ! -d "$entry" ]]; then
    echo "::error file=test/vectors/$name::not a directory copied from void-which-binds-go" >&2
    status=1
    continue
  fi
  if [[ ! -d "$upstream/$name" ]]; then
    echo "::error file=test/vectors/$name::void-which-binds-go@$ref has no testvectors/vectors/$name" >&2
    status=1
    continue
  fi
  if ! diff -r -u "$upstream/$name" "$entry"; then
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "vectors match void-which-binds-go@$ref"
else
  echo "::error::test/vectors has drifted from void-which-binds-go testvectors/vectors@$ref. Re-copy the directories from void-which-binds-go (never hand-edit them) and bump VOID_WHICH_BINDS_GO_REF in the same change." >&2
  exit 1
fi
