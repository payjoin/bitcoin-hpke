#!/usr/bin/env bash
#
# Pull request check. When the crate version changed relative to the base
# commit, confirm the bump is consistent (check-invariants), the crate still
# publishes (cargo publish --dry-run), and the bump is large enough for the
# API changes since the base version (cargo semver-checks). No-ops when the
# version did not change.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/release/crates.sh
source "$DIR/crates.sh"
cd "$REPO_ROOT"

[ "$#" -eq 1 ] || {
    echo "usage: check-bump.sh <base-sha>" >&2
    exit 1
}
base="$1"

# The [package] version at a git ref (the only line-anchored `version`).
version_at() {
    git show "$1:Cargo.toml" 2>/dev/null | sed -n 's/^version = "\(.*\)"/\1/p' | head -1
}

baseline="$(version_at "$base")"
version="$(manifest_version)"
echo "Comparing $CRATE version against $base"
if [ "$baseline" = "$version" ]; then
    echo "Version did not change ($version)"
    exit 0
fi

echo "Version changed: $baseline -> $version"
"$DIR/check-invariants.sh"

echo "Dry-run publishing $CRATE"
cargo publish --dry-run -q
echo "$CRATE packages and publishes cleanly"

# Semver only binds between stable releases: any comparison involving a
# pre-release is classified as a major bump, which permits everything, so
# running the tool there proves nothing.
if is_prerelease "$version" || is_prerelease "$baseline"; then
    echo "Skipping semver check for pre-release ($baseline -> $version)"
    exit 0
fi
if ! crate_published "$baseline"; then
    echo "Skipping semver check; baseline $baseline not on crates.io"
    exit 0
fi
echo "Checking $CRATE $version API against $baseline"
cargo semver-checks --baseline-version "$baseline"
