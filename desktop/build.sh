#!/usr/bin/env bash
set -e
export PATH="/snap/bin:/home/tom/go/bin:/usr/local/bin:/usr/bin:/bin"
cd /home/tom/IPLink/desktop

echo "Step 1: Cleaning previous syso files..."
rm -f *.syso

echo "Step 2: Generating Windows resources with transparent icons..."
go-winres make --arch amd64

echo "Step 3: Compiling Windows production binary with GUI subsystem..."
GOPROXY="https://goproxy.cn,direct" GOOS=windows GOARCH=amd64 go build \
  -tags "desktop,production" \
  -ldflags "-w -s -H windowsgui" \
  -o ../bin/iplink-desktop.exe .

echo "Build completed successfully -> bin/iplink-desktop.exe"
