#!/usr/bin/env bash
#
# After publishing, confirm crates.io reports a checksum matching the
# attested .crate and docs.rs built the docs. Runs after the upload, so a
# mismatch is a loud alert, not a gate. Poll counts and interval are
# overridable via the environment; the defaults suit CI.
set -euo pipefail
# shellcheck source=contrib/release/crates.sh
source "$(dirname "${BASH_SOURCE[0]}")/crates.sh"

[ "$#" -eq 2 ] || {
    echo "usage: verify-published.sh <version> <crate-file>" >&2
    exit 1
}
version="$1"
file="$2"
ua="bitcoin-hpke release verify-published"
interval="${POLL_INTERVAL:-10}"
die() {
    echo "verify-published: $*" >&2
    exit 1
}

# Poll a URL until its jq filter yields non-empty output; print it, or fail.
poll() {
    local attempts="$1" url="$2" filter="$3" out i
    for ((i = 0; i < attempts; i++)); do
        out="$(curl -sfL -H "User-Agent: $ua" "$url" 2>/dev/null | jq -r "$filter" 2>/dev/null || true)"
        [ -n "$out" ] && {
            printf '%s' "$out"
            return 0
        }
        sleep "$interval"
    done
    return 1
}

[ -f "$file" ] || die "no such file: $file"
local_sha="$(sha256sum "$file" | cut -d' ' -f1)"

echo "Waiting for $CRATE $version on crates.io (${CRATES_IO_ATTEMPTS:-30} checks, ${interval}s apart)"
published_sha="$(poll "${CRATES_IO_ATTEMPTS:-30}" \
    "https://crates.io/api/v1/crates/$CRATE/$version" '.version.checksum // empty')" ||
    die "$CRATE $version never appeared on crates.io"
[ "$published_sha" = "$local_sha" ] ||
    die "checksum mismatch: crates.io $published_sha vs local $local_sha"
echo "crates.io checksum matches the attested .crate ($local_sha)"

echo "Waiting for docs.rs to build $CRATE $version (${DOCS_RS_ATTEMPTS:-60} checks, ${interval}s apart)"
poll "${DOCS_RS_ATTEMPTS:-60}" \
    "https://docs.rs/crate/$CRATE/$version/status.json" 'select(.doc_status == true) | "built"' >/dev/null ||
    die "docs.rs did not build $CRATE $version"
echo "docs.rs built $CRATE $version"
