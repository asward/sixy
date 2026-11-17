#!/usr/bin/env bash
# Build the container image locally.
#   scripts/build.sh                 -> wanwatch:local
#   IMAGE=ghcr.io/asward/sixy:dev scripts/build.sh
#   PLATFORMS=linux/amd64,linux/arm64 PUSH=1 IMAGE=ghcr.io/asward/sixy:dev scripts/build.sh
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-wanwatch:local}"
REVISION="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"

if [[ -n "${PLATFORMS:-}" ]]; then
  # Multi-arch needs buildx; result must be pushed (or use --load for a single platform).
  docker buildx build --platform "$PLATFORMS" \
    --label "org.opencontainers.image.revision=$REVISION" \
    -t "$IMAGE" ${PUSH:+--push} .
else
  docker build --label "org.opencontainers.image.revision=$REVISION" -t "$IMAGE" .
fi
echo "Built $IMAGE ($REVISION)"
