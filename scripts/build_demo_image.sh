#!/usr/bin/env bash
set -euo pipefail
cat > Dockerfile <<'EOF'
FROM busybox:latest
CMD ["echo","hello, did/vc world"]
EOF
docker build -t local/demo:latest .
echo "Built local/demo:latest"
