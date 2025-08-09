#!/usr/bin/env bash
set -euo pipefail
IMG="${1:-local/demo:latest}"
if command -v skopeo >/dev/null; then
  skopeo inspect "docker-daemon:${IMG}" | jq -r .Digest
  exit 0
fi
if command -v crane >/dev/null; then
  crane digest "${IMG}"
  exit 0
fi
echo "Install 'skopeo' or 'crane' to extract manifest digest." >&2
exit 1
