#!/usr/bin/env bash
set -e
export PATH="/snap/bin:/home/tom/go/bin:/usr/local/bin:/usr/bin:/bin"
cd /home/tom/IPLink/desktop

echo "Step 0: Preparing transparent icons for winres..."
rm -f *.syso
python3 - << 'EOF'
from PIL import Image
appicon = Image.open("/home/tom/IPLink/desktop/build/appicon.png")
appicon.resize((256, 256), Image.Resampling.LANCZOS).save("/home/tom/IPLink/desktop/winres/icon256.png")
appicon.resize((48, 48), Image.Resampling.LANCZOS).save("/home/tom/IPLink/desktop/winres/icon48.png")
appicon.resize((32, 32), Image.Resampling.LANCZOS).save("/home/tom/IPLink/desktop/winres/icon32.png")
appicon.resize((16, 16), Image.Resampling.LANCZOS).save("/home/tom/IPLink/desktop/winres/icon16.png")
print("Icons prepped.")
EOF

echo "Step 1: Generating Windows resources (syso with AppIconID 3 and transparent icon)..."
go-winres make --arch amd64

echo "Step 2: Compiling Windows production binary with GUI subsystem..."
GOPROXY="https://goproxy.cn,direct" GOOS=windows GOARCH=amd64 go build \
  -tags "desktop,production" \
  -ldflags "-w -s -H windowsgui" \
  -o ../bin/iplink-desktop.exe .

echo "Build completed successfully -> bin/iplink-desktop.exe"
