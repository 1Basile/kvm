#!/bin/bash
set -e

SYSROOT=/opt/jetkvm-native-buildkit/arm-rockchip830-linux-uclibcgnueabihf/sysroot
CC=/opt/jetkvm-native-buildkit/bin/arm-rockchip830-linux-uclibcgnueabihf-gcc

echo "=== Cross-compiling libopus ==="
cd /tmp
wget -q https://downloads.xiph.org/releases/opus/opus-1.4.tar.gz
tar xf opus-1.4.tar.gz
cd opus-1.4
./configure --host=arm-linux-gnueabihf CC="$CC" \
  --prefix=/usr --disable-shared --enable-static \
  --disable-doc --disable-extra-programs -q
make -j$(nproc) -s
make DESTDIR="$SYSROOT" install -s
echo "=== libopus installed ==="

cd /build
git config --global --add safe.directory /build
echo "=== Building jetkvm_app ==="
make _build_dev_inner SKIP_NATIVE_IF_EXISTS=1
echo "=== Done: $(ls -lh /build/bin/jetkvm_app) ==="
