#!/usr/bin/env bash
# Usage: fetch-spec.sh <target-dir>
# Copies test vectors from $SQUADDLE_SPEC_DIR if set, else downloads the release pinned in SPEC_VERSION.
set -euo pipefail
target="$1"
rm -rf "$target" && mkdir -p "$target"
if [[ -n "${SQUADDLE_SPEC_DIR:-}" ]]; then
  cp -r "$SQUADDLE_SPEC_DIR/protocol/testvectors/." "$target/"
  echo "test vectors: local $SQUADDLE_SPEC_DIR"
  exit 0
fi
version="$(tr -d '[:space:]' < "$(dirname "$0")/../SPEC_VERSION")"
curl -fsSL "https://github.com/squaddle-org/spec/releases/download/${version}/testvectors.tar.gz" \
  | tar -xz -C "$target" --strip-components=1
echo "test vectors: spec ${version}"
