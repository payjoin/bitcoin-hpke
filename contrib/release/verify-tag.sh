#!/usr/bin/env bash
#
# Release gate. Confirms a `<version>` tag is annotated, signed by a key in
# contrib/release/keys/, an ancestor of origin/main, matches the manifest
# version, and satisfies the release invariants.
#
# Checks against the working tree, so run it at the tagged commit, which the
# release workflow does.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/release/crates.sh
source "$DIR/crates.sh"

[ "$#" -eq 1 ] || {
    echo "usage: verify-tag.sh <tag>" >&2
    exit 1
}
tag="$1"
die() {
    echo "verify-tag: $*" >&2
    exit 1
}

version="$(version_from_tag "$tag")" || die "$tag is not a <version> release tag"

echo "Verifying $tag as a release of $CRATE $version"

echo "Checking the tag is annotated"
[ "$(git -C "$REPO_ROOT" cat-file -t "$tag" 2>/dev/null)" = tag ] ||
    die "$tag is not an annotated tag"

echo "Checking the tag is signed by a key in contrib/release/keys/"
# The throwaway keyring holds only trusted keys, so a successful
# verification against it proves the signer is trusted.
home="$(mktemp -d)"
trap 'rm -rf "$home"' EXIT
gpg --homedir "$home" --batch --quiet --import "$REPO_ROOT"/contrib/release/keys/*.asc 2>/dev/null ||
    die "no importable keys in contrib/release/keys/"
GNUPGHOME="$home" git -C "$REPO_ROOT" verify-tag "$tag" >/dev/null 2>&1 ||
    die "$tag is not signed by a trusted key"

echo "Checking the tag is an ancestor of origin/main"
git -C "$REPO_ROOT" merge-base --is-ancestor "$tag" origin/main 2>/dev/null ||
    die "$tag is not an ancestor of origin/main"

echo "Checking the manifest version is $version"
manifest="$(manifest_version)"
[ "$manifest" = "$version" ] || die "manifest version is $manifest, tag says $version"

"$DIR/check-invariants.sh" || die "release invariants fail for $CRATE"

echo "$tag is cleared for release"
