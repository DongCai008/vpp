#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/images.env"

docker build \
  -t "$VPP_BUILD_IMAGE" \
  -f "$SCRIPT_DIR/Dockerfile" \
  "$VPP_DIR"
