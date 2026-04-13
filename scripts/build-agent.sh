#!/bin/bash
# Build labwatch agent binaries for all supported platforms.
# Output goes to server/dist/ so the /download/ route can serve them.
#
# Usage: ./scripts/build-agent.sh
# Requires: Go 1.21+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
AGENT_DIR="$ROOT_DIR/agent"
DIST_DIR="$ROOT_DIR/server/dist"

# Read version from main.go
VERSION=$(grep -oP 'version\s+=\s+"\K[^"]+' "$AGENT_DIR/cmd/labwatch/main.go" || echo "dev")
BUILD_DATE=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

echo "Building labwatch agent v${VERSION} (${BUILD_DATE})"
echo ""

mkdir -p "$DIST_DIR"

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
)

cd "$AGENT_DIR"

for target in "${TARGETS[@]}"; do
    GOOS="${target%%/*}"
    GOARCH="${target##*/}"

    # Map GOARCH to the names used in install.sh
    case "$GOARCH" in
        amd64) ARCH_NAME="amd64" ;;
        arm64) ARCH_NAME="arm64" ;;
        arm)   ARCH_NAME="armv7"; export GOARM=7 ;;
    esac

    OUTPUT="$DIST_DIR/labwatch-${GOOS}-${ARCH_NAME}"
    echo "  Building ${GOOS}/${GOARCH} → $(basename "$OUTPUT")"

    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
        -ldflags "-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE}" \
        -trimpath \
        -o "$OUTPUT" \
        ./cmd/labwatch/

    unset GOARM 2>/dev/null || true
done

echo ""
echo "Done. Binaries in $DIST_DIR:"
ls -lh "$DIST_DIR"/labwatch-*
