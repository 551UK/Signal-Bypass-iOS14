#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v ldid >/dev/null
command -v dpkg-deb >/dev/null
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p build package/DEBIAN package/Library/MobileSubstrate/DynamicLibraries
xcrun --sdk iphoneos clang -arch arm64 -isysroot "$SDK" \
  -miphoneos-version-min=14.0 -fobjc-arc -fblocks -O2 -Wall -Wextra \
  -Wno-unused-parameter -Werror -dynamiclib Tweak.m \
  -framework Foundation -framework UIKit \
  -install_name /Library/MobileSubstrate/DynamicLibraries/SignalBypass14.dylib \
  -o build/SignalBypass14.dylib
ldid -S build/SignalBypass14.dylib
cp build/SignalBypass14.dylib SignalBypass14.plist package/Library/MobileSubstrate/DynamicLibraries/
cp control package/DEBIAN/control
chmod 755 package package/DEBIAN package/Library package/Library/MobileSubstrate package/Library/MobileSubstrate/DynamicLibraries
chmod 644 package/DEBIAN/control package/Library/MobileSubstrate/DynamicLibraries/*
dpkg-deb --root-owner-group -Zgzip --build package build/uk.551.signalbypass14_0.1.0_iphoneos-arm.deb
dpkg-deb --info build/*.deb
dpkg-deb --contents build/*.deb
