#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
docker build -f "$REPO_ROOT/examples/demo-image/Dockerfile" -t local/demo:latest "$REPO_ROOT/examples/demo-image"
echo "Built local/demo:latest"
