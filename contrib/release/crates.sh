#!/usr/bin/env bash
#
# Shared helpers for the release scripts. bitcoin-hpke is a single crate at
# the repository root released with bare `<version>` tags, so this is a
# simplified port of rust-payjoin's contrib/release/crates.sh.

CRATE="bitcoin-hpke"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Print the crate's manifest version.
manifest_version() {
    cargo metadata --no-deps --format-version 1 --manifest-path "$REPO_ROOT/Cargo.toml" |
        jq -r --arg c "$CRATE" '.packages[] | select(.name == $c) | .version'
}

# Print the version in a bare `<version>` release tag, or fail.
version_from_tag() {
    case "$1" in
        [0-9]*) printf '%s' "$1" ;;
        *) return 1 ;;
    esac
}

# Succeed if the version has a semver pre-release suffix.
is_prerelease() {
    case "$1" in
        *-*) return 0 ;;
        *) return 1 ;;
    esac
}

# Succeed if <version> of the crate exists on crates.io.
crate_published() {
    curl -sfL -o /dev/null -H "User-Agent: bitcoin-hpke release tooling" \
        "https://crates.io/api/v1/crates/$CRATE/$1"
}
