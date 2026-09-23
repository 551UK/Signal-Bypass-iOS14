#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

command -v ldid >/dev/null
command -v dpkg-deb >/dev/null

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p build package/DEBIAN package/Library/MobileSubstrate/DynamicLibraries
mkdir -p package/usr/libexec

# Signal 7.19.1 bundles libsignal 0.52, whose CDSI handshake cannot
# speak the live post-quantum service. v0.71.0 is PQ-capable and still targets
# iOS 13, but its CDSI advisory map is compiled against the retired c6ff...
# enclave. Build that exact official source with only ENCLAVE_ID_CDSI updated
# to the current Signal 8.29 production enclave.
LIBSIGNAL71_VERSION="0.71.0"
LIBSIGNAL71_COMMIT="eac4cf58ed9b102778b477a9657d4a348cf28f9c"
LIBSIGNAL71_SRC="build/libsignal71-src"
LIBSIGNAL71_OLD_CDSI="c6ff0682219217f7045624be472a077c0d4b06193fe71632eb0adb50051d5da1"
LIBSIGNAL71_NEW_CDSI="15637fa1e54fe655176d3df1a9f94b87c01ed377acaa570682dc5d72c95ef07b"

rm -rf "${LIBSIGNAL71_SRC}"
git clone --depth 1 --branch "v${LIBSIGNAL71_VERSION}" \
  https://github.com/signalapp/libsignal.git "${LIBSIGNAL71_SRC}"
[[ "$(git -C "${LIBSIGNAL71_SRC}" rev-parse HEAD)" == "${LIBSIGNAL71_COMMIT}" ]] || {
  echo "Unexpected libsignal v${LIBSIGNAL71_VERSION} commit"
  git -C "${LIBSIGNAL71_SRC}" rev-parse HEAD
  exit 1
}

python3 - "${LIBSIGNAL71_SRC}/rust/attest/src/constants.rs" \
  "${LIBSIGNAL71_OLD_CDSI}" "${LIBSIGNAL71_NEW_CDSI}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
text = path.read_text()
count = text.count(old)
if count != 1:
    raise SystemExit(f"expected exactly one old CDSI enclave in {path}, found {count}")
path.write_text(text.replace(old, new))
check = path.read_text()
if old in check or check.count(new) != 1:
    raise SystemExit("CDSI source patch verification failed")
print("Patched libsignal 0.71 ENCLAVE_ID_CDSI at source level:", new)
PY

(
  cd "${LIBSIGNAL71_SRC}"
  rustup target add aarch64-apple-ios
  CARGO_BUILD_TARGET=aarch64-apple-ios ./swift/build_ffi.sh --release
)

LIBSIGNAL71_STATIC="${LIBSIGNAL71_SRC}/target/aarch64-apple-ios/release/libsignal_ffi.a"
[[ -f "${LIBSIGNAL71_STATIC}" ]] || {
  echo "Could not find source-built libsignal 0.71 iOS static library"
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

dpkg-deb --root-owner-group -Zgzip --build package build/uk.551.signalbypass14_1.5.12_iphoneos-arm.deb

dpkg-deb --info build/uk.551.signalbypass14_1.5.12_iphoneos-arm.deb
dpkg-deb --contents build/uk.551.signalbypass14_1.5.12_iphoneos-arm.deb
