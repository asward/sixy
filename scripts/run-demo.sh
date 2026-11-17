#!/usr/bin/env bash
# Build and run the container in demo mode (fake scan results, no Google account).
# Open http://localhost:8080 afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-wanwatch:local}" scripts/build.sh
docker rm -f wanwatch-demo >/dev/null 2>&1 || true
docker run -d --name wanwatch-demo -p "${PORT:-8080}:8080" -e SCAN_BACKEND=demo "${IMAGE:-wanwatch:local}"
echo "Demo running on http://localhost:${PORT:-8080}  (stop: docker rm -f wanwatch-demo)"
