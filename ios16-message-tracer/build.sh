#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
command -v ldid >/dev/null
command -v dpkg-deb >/dev/null
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
rm -rf build package
mkdir -p build package/DEBIAN package/var/jb/Library/MobileSubstrate/DynamicLibraries

xcrun --sdk iphoneos clang -arch arm64 -arch arm64e -isysroot "$SDK" \
  -miphoneos-version-min=16.0 -fobjc-arc -fblocks -O2 -Wall -Wextra \
  -Wno-unused-parameter -Wno-deprecated-declarations -dynamiclib Tweak.m \
  -framework Foundation \
  -install_name /var/jb/Library/MobileSubstrate/DynamicLibraries/SignalMessageTracer16.dylib \
  -o build/SignalMessageTracer16.dylib

ARCHS="$(xcrun lipo -archs build/SignalMessageTracer16.dylib)"
echo "Architectures: $ARCHS"
[[ "$ARCHS" == *arm64* && "$ARCHS" == *arm64e* ]]
ldid -S build/SignalMessageTracer16.dylib

cp build/SignalMessageTracer16.dylib package/var/jb/Library/MobileSubstrate/DynamicLibraries/
cp SignalMessageTracer16.plist package/var/jb/Library/MobileSubstrate/DynamicLibraries/
cp control package/DEBIAN/control

chmod 755 package package/DEBIAN package/var package/var/jb package/var/jb/Library package/var/jb/Library/MobileSubstrate package/var/jb/Library/MobileSubstrate/DynamicLibraries
chmod 755 package/var/jb/Library/MobileSubstrate/DynamicLibraries/SignalMessageTracer16.dylib
chmod 644 package/var/jb/Library/MobileSubstrate/DynamicLibraries/SignalMessageTracer16.plist package/DEBIAN/control

dpkg-deb --root-owner-group -Zgzip --build package build/uk.551.signalmessagetracer16_0.1.0_iphoneos-arm64.deb
dpkg-deb --info build/*.deb
dpkg-deb --contents build/*.deb
