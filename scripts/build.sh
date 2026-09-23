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


# Build a second helper from the exact libsignal version bundled by Signal 7.19.1.
# Keep SenderCertificate's Rust struct layout unchanged, but teach only its parser
# about the current compact certificate wire format (UUID bytes + signer id).
LIBSIGNAL52_VERSION="0.52.0"
LIBSIGNAL52_COMMIT="e13e3de8b25c8204b9bb5f04cc50dd12e7f40fc3"
LIBSIGNAL52_SRC="build/libsignal52-sendercert"

rm -rf "${LIBSIGNAL52_SRC}"
git clone --depth 1 --branch "v${LIBSIGNAL52_VERSION}" \
  https://github.com/signalapp/libsignal.git "${LIBSIGNAL52_SRC}"
[[ "$(git -C "${LIBSIGNAL52_SRC}" rev-parse HEAD)" == "${LIBSIGNAL52_COMMIT}" ]] || {
  echo "Unexpected libsignal v${LIBSIGNAL52_VERSION} commit"
  git -C "${LIBSIGNAL52_SRC}" rev-parse HEAD
  exit 1
}

python3 - "${LIBSIGNAL52_SRC}" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
proto = root / "rust/protocol/src/proto/sealed_sender.proto"
rs = root / "rust/protocol/src/sealed_sender.rs"

old_proto = """message SenderCertificate {
    message Certificate {
        optional string            senderE164    = 1;
        optional string            senderUuid    = 6;
        optional uint32            senderDevice  = 2;
        optional fixed64           expires       = 3;
        optional bytes             identityKey   = 4;
        optional ServerCertificate signer        = 5;
    }

    optional bytes certificate = 1;
    optional bytes signature   = 2;
}"""
new_proto = """message SenderCertificate {
    message Certificate {
        optional string            senderE164    = 1;
        oneof senderUuid {
            string                 uuidString    = 6;
            bytes                  uuidBytes     = 7;
        }
        optional uint32            senderDevice  = 2;
        optional fixed64           expires       = 3;
        optional bytes             identityKey   = 4;
        oneof signer {
            bytes /*ServerCertificate*/ certificate = 5;
            uint32                      id          = 8;
        }
    }

    optional bytes certificate = 1;
    optional bytes signature   = 2;
}"""

text = proto.read_text()
if text.count(old_proto) != 1:
    raise SystemExit("old SenderCertificate proto block not found exactly once")
proto.write_text(text.replace(old_proto, new_proto))

old_parse = """        let signer_pb = certificate_data
            .signer
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_uuid = certificate_data
            .sender_uuid
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_e164 = certificate_data.sender_e164;

        let key = PublicKey::try_from(
            &certificate_data
                .identity_key
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?[..],
        )?;

        let signer_bits = signer_pb.encode_to_vec();
        let signer = ServerCertificate::deserialize(&signer_bits)?;"""

new_parse = """        let signer = match certificate_data
            .signer
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
        {
            proto::sealed_sender::sender_certificate::certificate::Signer::Certificate(encoded) => {
                ServerCertificate::deserialize(&encoded)?
            }
            proto::sealed_sender::sender_certificate::certificate::Signer::Id(id) => {
                // Current Signal production uses signer id 3. Keep staging id 2
                // as well so this remains a faithful compatibility parser.
                let encoded_hex = match id {
                    2 => "0a25080212210539450d63ebd0752c0fd4038b9d07a916f5e174b756d409b5ca79f4c97400631e124064c5a38b1e927497d3d4786b101a623ab34a7da3954fae126b04dba9d7a3604ed88cdc8550950f0d4a9134ceb7e19b94139151d2c3d6e1c81e9d1128aafca806",
                    3 => "0a250803122105bc9d1d290be964810dfa7e94856480a3f7060d004c9762c24c575a1522353a5a1240c11ec3c401eb0107ab38f8600e8720a63169e0e2eb8a3fae24f63099f85ea319c3c1c46d3454706ae2a679d1fee690a488adda98a2290b66c906bb60295ed781",
                    _ => return Err(SignalProtocolError::InvalidProtobufEncoding),
                };
                let encoded = hex::decode(encoded_hex)
                    .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
                ServerCertificate::deserialize(&encoded)?
            }
        };

        let sender_uuid = match certificate_data
            .sender_uuid
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
        {
            proto::sealed_sender::sender_certificate::certificate::SenderUuid::UuidString(value) => value,
            proto::sealed_sender::sender_certificate::certificate::SenderUuid::UuidBytes(raw) => {
                uuid::Uuid::from_slice(&raw)
                    .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?
                    .to_string()
            }
        };
        let sender_e164 = certificate_data.sender_e164;

        let key = PublicKey::try_from(
            &certificate_data
                .identity_key
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?[..],
        )?;"""

text = rs.read_text()
if text.count(old_parse) != 1:
    raise SystemExit("old SenderCertificate parse block not found exactly once")
text = text.replace(old_parse, new_parse)

old_new = """        let certificate_pb = proto::sealed_sender::sender_certificate::Certificate {
            sender_uuid: Some(sender_uuid.clone()),
            sender_e164: sender_e164.clone(),
            sender_device: Some(sender_device_id.into()),
            expires: Some(expiration.epoch_millis()),
            identity_key: Some(key.serialize().to_vec()),
            signer: Some(signer.to_protobuf()?),
        };"""

new_new = """        let certificate_pb = proto::sealed_sender::sender_certificate::Certificate {
            sender_uuid: Some(
                proto::sealed_sender::sender_certificate::certificate::SenderUuid::UuidString(
                    sender_uuid.clone(),
                ),
            ),
            sender_e164: sender_e164.clone(),
            sender_device: Some(sender_device_id.into()),
            expires: Some(expiration.epoch_millis()),
            identity_key: Some(key.serialize().to_vec()),
            signer: Some(
                proto::sealed_sender::sender_certificate::certificate::Signer::Certificate(
                    signer.serialized()?.to_vec(),
                ),
            ),
        };"""

if text.count(old_new) != 1:
    raise SystemExit("old SenderCertificate constructor block not found exactly once")
rs.write_text(text.replace(old_new, new_new))

print("Patched libsignal 0.52 sender-certificate wire parser while preserving struct layout")
PY

(
  cd "${LIBSIGNAL52_SRC}"
  rustup target add aarch64-apple-ios
  CARGO_BUILD_TARGET=aarch64-apple-ios ./swift/build_ffi.sh --release
)

LIBSIGNAL52_STATIC="${LIBSIGNAL52_SRC}/target/aarch64-apple-ios/release/libsignal_ffi.a"
[[ -f "${LIBSIGNAL52_STATIC}" ]] || {
  echo "Could not find source-built libsignal 0.52 iOS static library"
  exit 1
}

xcrun --sdk iphoneos clang -arch arm64 -isysroot "$SDK" \
  -miphoneos-version-min=14.0 -O2 -Wall -Wextra -Werror -dynamiclib \
  SenderCertBridge.c "${LIBSIGNAL52_STATIC}" \
  -Wl,-exported_symbols_list,SenderCertBridge.exports \
  -framework Foundation -framework CoreFoundation -framework Security -lc++ \
  -install_name /Library/MobileSubstrate/DynamicLibraries/SignalSenderCertBridge.dylib \
  -o build/SignalSenderCertBridge.dylib

ldid -S build/SignalSenderCertBridge.dylib

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
cp build/SignalSenderCertBridge.dylib package/Library/MobileSubstrate/DynamicLibraries/
cp control package/DEBIAN/control

chmod 755 package package/DEBIAN package/Library package/Library/MobileSubstrate package/Library/MobileSubstrate/DynamicLibraries
chmod 644 package/DEBIAN/control package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.plist
chmod 755 package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.dylib
chmod 755 package/Library/MobileSubstrate/DynamicLibraries/SignalCdsiPQBridge.dylib
chmod 755 package/Library/MobileSubstrate/DynamicLibraries/SignalSenderCertBridge.dylib

DYLIB_MODE="$(stat -f '%Lp' package/Library/MobileSubstrate/DynamicLibraries/SignalBypass14.dylib)"
BRIDGE_MODE="$(stat -f '%Lp' package/Library/MobileSubstrate/DynamicLibraries/SignalCdsiPQBridge.dylib)"
CERT_BRIDGE_MODE="$(stat -f '%Lp' package/Library/MobileSubstrate/DynamicLibraries/SignalSenderCertBridge.dylib)"
[[ "$DYLIB_MODE" == "755" && "$BRIDGE_MODE" == "755" && "$CERT_BRIDGE_MODE" == "755" ]] || {
  echo "Bad rootful dylib mode: tweak=$DYLIB_MODE cdsi=$BRIDGE_MODE cert=$CERT_BRIDGE_MODE"
  exit 1
}

dpkg-deb --root-owner-group -Zgzip --build package build/uk.551.signalbypass14_1.5.15_iphoneos-arm.deb

dpkg-deb --info build/uk.551.signalbypass14_1.5.15_iphoneos-arm.deb
dpkg-deb --contents build/uk.551.signalbypass14_1.5.15_iphoneos-arm.deb
