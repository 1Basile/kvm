#!/bin/bash
set -e

KERNEL_DIR=/tmp/jetkvm-kernel/sysdrv/source/kernel
ARCH=arm
CROSS_COMPILE=/opt/jetkvm-native-buildkit/bin/arm-rockchip830-linux-uclibcgnueabihf-
DEFCONFIG=rv1106-jetkvm-v2_defconfig
OUTPUT_DIR=/build/bin

echo "=== Preparing kernel build environment ==="
cd "$KERNEL_DIR"

# Apply defconfig
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE $DEFCONFIG -j$(nproc) -s

# Enable UAC2 as module in .config
echo "CONFIG_USB_F_UAC2=m" >> .config
echo "CONFIG_USB_LIBCOMPOSITE=y" >> .config

# Resolve any config dependencies
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE olddefconfig -s

# Generate kernel headers and Module.symvers (no full kernel compile needed)
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE modules_prepare -j$(nproc) -s

echo "=== Building usb_f_uac2.ko ==="
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE \
  M=drivers/usb/gadget/function \
  CONFIG_USB_F_UAC2=m \
  modules -j$(nproc) -s

# Copy the built module
cp drivers/usb/gadget/function/usb_f_uac2.ko "$OUTPUT_DIR/"
echo "=== Done: $(ls -lh $OUTPUT_DIR/usb_f_uac2.ko) ==="

# Verify vermagic matches device
VERMAGIC=$(strings "$OUTPUT_DIR/usb_f_uac2.ko" | grep vermagic)
echo "Module vermagic: $VERMAGIC"
echo "Expected:        vermagic=5.10.160 mod_unload ARMv7 thumb2 p2v8"
