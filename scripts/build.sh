#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

command -v ldid >/dev/null
command -v dpkg-deb >/dev/null

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p build package/DEBIAN package/Library/MobileSubstrate/DynamicLibraries
mkdir -p package/usr/libexec

xcrun --sdk iphoneos clang -arch arm64 -arch arm64e -isysroot "$SDK" \
  -miphoneos-version-min=14.0 -fobjc-arc -O2 -Wall -Wextra \
  -Wno-unused-parameter -Werror -dynamiclib Tweak.m \
  -framework Foundation \
  -install_name /Library/MobileSubstrate/DynamicLibraries/SignalBypass14.dylib \
  -o build/SignalBypass14.dylib

xcrun lipo -archs build/SignalBypass14.dylib
ARCHS="$(xcrun lipo -archs build/SignalBypass14.dylib)"
[[ "$ARCHS" == *arm64* && "$ARCHS" == *arm64e* ]] || {
  echo "Missing required rootful architectures: $ARCHS"
  exit 1
}

ldid -S build/SignalBypass14.dylib

xcrun --sdk iphoneos clang -arch arm64 -arch arm64e -isysroot "$SDK" \
  -miphoneos-version-min=14.0 -fobjc-arc -O2 -Wall -Wextra -Werror \
  -Wno-deprecated-declarations BuildDate.m -framework Foundation \
  -o build/signalbypass14-builddate

ldid -S build/signalbypass14-builddate

cp build/signalbypass14-builddate package/usr/libexec/
cp scripts/postinst scripts/prerm package/DEBIAN/
chmod 755 package/usr package/usr/libexec package/usr/libexec/signalbypass14-builddate package/DEBIAN/postinst package/DEBIAN/prerm

cp build/SignalBypass14.dylib SignalBypass14.plist package/Library/MobileSubstrate/DynamicLibraries/
cp control package/DEBIAN/control

chmod 755 package package/DEBIAN package/Library package/Library/MobileSubstrate package/Library/MobileSubstrate/DynamicLibraries
chmod 644 package/DEBIAN/control package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.plist
chmod 755 package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.dylib

DYLIB_MODE="$(stat -f '%Lp' package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.dylib)"
[[ "$DYLIB_MODE" == "755" ]] || {
  echo "Bad rootful dylib mode: $DYLIB_MODE"
  exit 1
}

dpkg-deb --root-owner-group -Zgzip --build package build/uk.551.signalbypass14_1.4.0_iphoneos-arm.deb

dpkg-deb --info build/uk.551.signalbypass14_1.4.0_iphoneos-arm.deb
dpkg-deb --contents build/uk.551.signalbypass14_1.4.0_iphoneos-arm.deb
