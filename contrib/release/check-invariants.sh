#!/usr/bin/env bash
#
# Check that the release is internally consistent: CHANGELOG.md has a
# section for the manifest version. Offline, a few seconds.
set -euo pipefail
# shellcheck source=contrib/release/crates.sh
source "$(dirname "${BASH_SOURCE[0]}")/crates.sh"

version="$(manifest_version)"
echo "Checking $CRATE $version: CHANGELOG.md"
grep -q "^## \[$version\]" "$REPO_ROOT/CHANGELOG.md" || {
    echo "CHANGELOG.md has no ## [$version] section" >&2
    exit 1
}
echo "Release invariants hold for $CRATE $version"
