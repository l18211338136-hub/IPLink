#!/usr/bin/env bash
set -euo pipefail

# Resolve paths relative to this script so the build works from any checkout.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Step 1: Cleaning previous syso files..."
rm -f *.syso

echo "Step 2: Generating Windows resources"
go-winres make --arch amd64

echo "Step 3: Compiling Windows production binary with GUI subsystem"
GOPROXY="https://goproxy.cn,direct" GOOS=windows GOARCH=amd64 go build \
  -tags "desktop,production" \
  -ldflags "-w -s -H windowsgui" \
  -o "$SCRIPT_DIR/../bin/iplink-desktop.exe" .

echo "Build completed successfully -> bin/iplink-desktop.exe"
