#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

command -v ldid >/dev/null
command -v dpkg-deb >/dev/null

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p build package/DEBIAN package/Library/MobileSubstrate/DynamicLibraries
mkdir -p package/usr/libexec

# Signal 7.19.1 bundles libsignal 0.52, whose CDSI Noise handshake is pre-PQ.
# Keep v0.71.0 because it is PQ-capable and officially supports iOS 13/14.
# v1.5.11 patches only its stale CDSI enclave advisory-map key at runtime.
LIBSIGNAL71_VERSION="0.71.0"
LIBSIGNAL71_SHA256="0bcf7d7255f153920ffa6cf03fe84a831a995347c767cd9f72463411296a0616"
LIBSIGNAL71_ARCHIVE="build/libsignal-client-ios-build-v${LIBSIGNAL71_VERSION}.tar.gz"
LIBSIGNAL71_DIR="build/libsignal71"

curl -fL --retry 3 \
  "https://build-artifacts.signal.org/libraries/libsignal-client-ios-build-v${LIBSIGNAL71_VERSION}.tar.gz" \
  -o "${LIBSIGNAL71_ARCHIVE}"
printf '%s  %s\n' "${LIBSIGNAL71_SHA256}" "${LIBSIGNAL71_ARCHIVE}" | shasum -a 256 -c -

rm -rf "${LIBSIGNAL71_DIR}"
mkdir -p "${LIBSIGNAL71_DIR}"
tar -m -x -f "${LIBSIGNAL71_ARCHIVE}" -C "${LIBSIGNAL71_DIR}"
LIBSIGNAL71_STATIC="$(find "${LIBSIGNAL71_DIR}" -type f -path '*/aarch64-apple-ios/release/libsignal_ffi.a' -print -quit)"
[[ -n "${LIBSIGNAL71_STATIC}" && -f "${LIBSIGNAL71_STATIC}" ]] || {
  echo "Could not find libsignal 0.71 iOS static library"
  find "${LIBSIGNAL71_DIR}" -maxdepth 6 -type f | sort
  exit 1
}

xcrun --sdk iphoneos clang -arch arm64 -isysroot "$SDK" \
  -miphoneos-version-min=14.0 -O2 -Wall -Wextra -Werror -dynamiclib \
  CdsiPQBridge.c "${LIBSIGNAL71_STATIC}" \
  -Wl,-exported_symbols_list,CdsiPQBridge.exports \
  -framework Foundation -framework CoreFoundation -framework Security -lc++ \
  -install_name /Library/MobileSubstrate/DynamicLibraries/SignalCdsiPQBridge.dylib \
  -o build/SignalCdsiPQBridge.dylib

ldid -S build/SignalCdsiPQBridge.dylib

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
cp build/SignalCdsiPQBridge.dylib package/Library/MobileSubstrate/DynamicLibraries/
cp control package/DEBIAN/control

chmod 755 package package/DEBIAN package/Library package/Library/MobileSubstrate package/Library/MobileSubstrate/DynamicLibraries
chmod 644 package/DEBIAN/control package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.plist
chmod 755 package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.dylib
chmod 755 package/Library/MobileSubstrate/DynamicLibraries/SignalCdsiPQBridge.dylib

DYLIB_MODE="$(stat -f '%Lp' package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.dylib)"
BRIDGE_MODE="$(stat -f '%Lp' package/Library/MobileSubstrate/DynamicLibraries/SignalCdsiPQBridge.dylib)"
[[ "$DYLIB_MODE" == "755" && "$BRIDGE_MODE" == "755" ]] || {
  echo "Bad rootful dylib mode: tweak=$DYLIB_MODE bridge=$BRIDGE_MODE"
  exit 1
}

dpkg-deb --root-owner-group -Zgzip --build package build/uk.551.signalbypass14_1.5.11_iphoneos-arm.deb

dpkg-deb --info build/uk.551.signalbypass14_1.5.11_iphoneos-arm.deb
dpkg-deb --contents build/uk.551.signalbypass14_1.5.11_iphoneos-arm.deb
