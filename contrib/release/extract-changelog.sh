#!/usr/bin/env bash
#
# Print the CHANGELOG.md section for a version: the lines between the
# `## [<version>]` heading and the next `## `, with blank edges trimmed.
# Used to fill the GitHub release body.
set -euo pipefail
# shellcheck source=contrib/release/crates.sh
source "$(dirname "${BASH_SOURCE[0]}")/crates.sh"

[ "$#" -eq 1 ] || {
    echo "usage: extract-changelog.sh <version>" >&2
    exit 1
}

# awk matches the heading as a literal prefix (the heading carries a date
# suffix and a version has regex-special dots); sed drops leading blank
# lines and the command substitution drops trailing ones.
section="$(awk -v h="## [$1]" '
    index($0, h) == 1 { inside = 1; next }
    inside && /^## / { exit }
    inside
' "$REPO_ROOT/CHANGELOG.md" | sed '/./,$!d')"

[ -n "$section" ] || {
    echo "extract-changelog: no ## [$1] section in CHANGELOG.md" >&2
    exit 1
}
printf '%s\n' "$section"
