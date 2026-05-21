#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/schlussel-xcframework.XXXXXX")"

FRAMEWORK_NAME="Schlussel"
STATIC_LIB_NAME="libschlussel_ffi.a"
CRATE_NAME="schlussel-ffi"
FRAMEWORK_VERSION="${SCHLUSSEL_FRAMEWORK_VERSION:-0.0.0-dev}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-U6LC622NKF}"
APPLE_CERTIFICATE_NAME="${APPLE_CERTIFICATE_NAME:-Developer ID Application: Tuist GmbH (${APPLE_TEAM_ID})}"
MACOS_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET:-12.0}"
SKIP_SIGNING="${SCHLUSSEL_SKIP_SIGNING:-0}"

KEYCHAIN_PATH="$TMP_DIR/signing.keychain-db"
KEYCHAIN_PASSWORD="$(uuidgen)"
CERTIFICATE_PATH="$TMP_DIR/certificate.p12"
C_MODULE_DIR="$TMP_DIR/cmodule"
ORIGINAL_DEFAULT_KEYCHAIN=""
KEYCHAIN_CREATED=0

cleanup() {
    if [[ "$KEYCHAIN_CREATED" == "1" ]]; then
        if [[ -n "$ORIGINAL_DEFAULT_KEYCHAIN" ]]; then
            security default-keychain -d user -s "$ORIGINAL_DEFAULT_KEYCHAIN" >/dev/null 2>&1 || true
        fi
        security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

json_field() {
    local field="$1"
    python3 -c '
import json
import sys

field = sys.argv[1]
data = json.load(sys.stdin)
value = data.get(field, "")
print("" if value is None else value)
' "$field"
}

read_secrets() {
    if [[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
        require_command op
        APPLE_ID_VALUE="$(op read --force "op://tuist/App Specific Password/username")"
        APPLE_PASSWORD_VALUE="$(op read --force "op://tuist/App Specific Password/password")"
        CERTIFICATE_PASSWORD_VALUE="$(op read --force "op://tuist/Developer ID Application Certificate/password")"
        op read --force "op://tuist/Developer ID Application Certificate/certificate.p12" \
            --out-file "$CERTIFICATE_PATH"
        return
    fi

    : "${APPLE_ID:?APPLE_ID must be set when OP_SERVICE_ACCOUNT_TOKEN is not available}"
    : "${APP_SPECIFIC_PASSWORD:?APP_SPECIFIC_PASSWORD must be set when OP_SERVICE_ACCOUNT_TOKEN is not available}"
    : "${APPLE_CERTIFICATE_PASSWORD:?APPLE_CERTIFICATE_PASSWORD must be set when OP_SERVICE_ACCOUNT_TOKEN is not available}"
    : "${APPLE_CERTIFICATE_P12_BASE64:?APPLE_CERTIFICATE_P12_BASE64 must be set when OP_SERVICE_ACCOUNT_TOKEN is not available}"

    APPLE_ID_VALUE="$APPLE_ID"
    APPLE_PASSWORD_VALUE="$APP_SPECIFIC_PASSWORD"
    CERTIFICATE_PASSWORD_VALUE="$APPLE_CERTIFICATE_PASSWORD"
    APPLE_CERTIFICATE_P12_BASE64="$APPLE_CERTIFICATE_P12_BASE64" \
        CERTIFICATE_PATH="$CERTIFICATE_PATH" \
        python3 - <<'PY'
import base64
import os
from pathlib import Path

payload = os.environ["APPLE_CERTIFICATE_P12_BASE64"]
Path(os.environ["CERTIFICATE_PATH"]).write_bytes(base64.b64decode(payload))
PY
}

setup_signing_keychain() {
    ORIGINAL_DEFAULT_KEYCHAIN="$(security default-keychain -d user | tr -d '"')"
    security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
    security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
    security default-keychain -d user -s "$KEYCHAIN_PATH"
    security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
    security import "$CERTIFICATE_PATH" -P "$CERTIFICATE_PASSWORD_VALUE" -A
    KEYCHAIN_CREATED=1
}

prepare_c_module() {
    mkdir -p "$C_MODULE_DIR"
    cp "$ROOT_DIR/include/schlussel.h" "$C_MODULE_DIR/schlussel.h"
    cat >"$C_MODULE_DIR/module.modulemap" <<'EOF'
module CSchlussel [system] {
  header "schlussel.h"
  export *
}
EOF
}

build_static_libraries() {
    rustup target add aarch64-apple-darwin x86_64-apple-darwin

    MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
        cargo build --release -p "$CRATE_NAME" --target aarch64-apple-darwin
    MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
        cargo build --release -p "$CRATE_NAME" --target x86_64-apple-darwin
}

build_swift_library() {
    local rust_target="$1"
    local swift_target="$2"
    local module_prefix="$3"
    local output_dir="$4"
    local rust_staticlib="$ROOT_DIR/target/$rust_target/release/$STATIC_LIB_NAME"
    local sdk_path
    sdk_path="$(xcrun --sdk macosx --show-sdk-path)"

    mkdir -p "$output_dir"

    MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
        xcrun --sdk macosx swiftc \
            "$ROOT_DIR/swift/Sources/Schlussel.swift" \
            -swift-version 6 \
            -target "$swift_target" \
            -sdk "$sdk_path" \
            -parse-as-library \
            -emit-library \
            -emit-module \
            -module-name "$FRAMEWORK_NAME" \
            -enable-library-evolution \
            -I "$C_MODULE_DIR" \
            "$rust_staticlib" \
            -framework CoreServices \
            -framework CoreFoundation \
            -liconv \
            -Xlinker -install_name \
            -Xlinker "@rpath/$FRAMEWORK_NAME.framework/Versions/A/$FRAMEWORK_NAME" \
            -emit-module-path "$output_dir/$module_prefix.swiftmodule" \
            -emit-module-interface-path "$output_dir/$module_prefix.swiftinterface" \
            -emit-module-source-info-path "$output_dir/$module_prefix.swiftsourceinfo" \
            -o "$output_dir/$FRAMEWORK_NAME"
}

write_framework_metadata() {
    local framework_dir="$1"

    cat >"$framework_dir/Versions/A/Resources/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>Schlussel</string>
  <key>CFBundleIdentifier</key>
  <string>dev.tuist.schlussel</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Schlussel</string>
  <key>CFBundlePackageType</key>
  <string>FMWK</string>
  <key>CFBundleShortVersionString</key>
  <string>${FRAMEWORK_VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${FRAMEWORK_VERSION}</string>
  <key>MinimumOSVersion</key>
  <string>12.0</string>
</dict>
</plist>
EOF
}

copy_module_artifacts() {
    local source_dir="$1"
    local destination_dir="$2"
    local module_prefix="$3"

    for extension in \
        abi.json \
        private.swiftinterface \
        swiftdoc \
        swiftinterface \
        swiftmodule \
        swiftsourceinfo
    do
        local source_file="$source_dir/$module_prefix.$extension"
        if [[ -f "$source_file" ]]; then
            cp "$source_file" "$destination_dir/"
        fi
    done
}

assemble_framework() {
    local framework_dir="$BUILD_DIR/$FRAMEWORK_NAME.framework"
    local arm64_dir="$TMP_DIR/swift-arm64"
    local x86_64_dir="$TMP_DIR/swift-x86_64"
    local module_dir="$framework_dir/Versions/A/Modules/$FRAMEWORK_NAME.swiftmodule"

    rm -rf \
        "$BUILD_DIR/$FRAMEWORK_NAME.framework" \
        "$BUILD_DIR/$FRAMEWORK_NAME.xcframework" \
        "$BUILD_DIR/$FRAMEWORK_NAME.xcframework.zip" \
        "$BUILD_DIR/$FRAMEWORK_NAME.framework.notarization.zip"
    mkdir -p "$BUILD_DIR"

    mkdir -p \
        "$module_dir" \
        "$framework_dir/Versions/A/Resources"

    write_framework_metadata "$framework_dir"

    build_swift_library \
        aarch64-apple-darwin \
        "arm64-apple-macosx${MACOS_DEPLOYMENT_TARGET}" \
        "arm64-apple-macos" \
        "$arm64_dir"
    build_swift_library \
        x86_64-apple-darwin \
        "x86_64-apple-macosx${MACOS_DEPLOYMENT_TARGET}" \
        "x86_64-apple-macos" \
        "$x86_64_dir"

    lipo -create "$arm64_dir/$FRAMEWORK_NAME" "$x86_64_dir/$FRAMEWORK_NAME" \
        -output "$framework_dir/Versions/A/$FRAMEWORK_NAME"
    chmod 755 "$framework_dir/Versions/A/$FRAMEWORK_NAME"

    copy_module_artifacts "$arm64_dir" "$module_dir" "arm64-apple-macos"
    copy_module_artifacts "$x86_64_dir" "$module_dir" "x86_64-apple-macos"

    ln -sfn A "$framework_dir/Versions/Current"
    ln -sfn Versions/Current/Resources "$framework_dir/Resources"
    ln -sfn Versions/Current/Modules "$framework_dir/Modules"
    ln -sfn Versions/Current/$FRAMEWORK_NAME "$framework_dir/$FRAMEWORK_NAME"
}

sign_framework() {
    /usr/bin/codesign \
        --force \
        --timestamp \
        --options runtime \
        --sign "$APPLE_CERTIFICATE_NAME" \
        "$BUILD_DIR/$FRAMEWORK_NAME.framework"
}

notarize_framework() {
    (
        cd "$BUILD_DIR"
        zip -q -r --symlinks "$FRAMEWORK_NAME.framework.notarization.zip" "$FRAMEWORK_NAME.framework"
    )

    local raw_json
    raw_json="$(
        xcrun notarytool submit "$BUILD_DIR/$FRAMEWORK_NAME.framework.notarization.zip" \
            --wait \
            --apple-id "$APPLE_ID_VALUE" \
            --team-id "$APPLE_TEAM_ID" \
            --password "$APPLE_PASSWORD_VALUE" \
            --output-format json
    )"

    local status
    status="$(printf '%s' "$raw_json" | json_field status)"
    if [[ "$status" != "Accepted" ]]; then
        local submission_id
        submission_id="$(printf '%s' "$raw_json" | json_field id)"
        if [[ -n "$submission_id" ]]; then
            xcrun notarytool log "$submission_id" \
                --apple-id "$APPLE_ID_VALUE" \
                --team-id "$APPLE_TEAM_ID" \
                --password "$APPLE_PASSWORD_VALUE" || true
        fi
        echo "Framework notarization failed with status: $status" >&2
        exit 1
    fi

    rm -f "$BUILD_DIR/$FRAMEWORK_NAME.framework.notarization.zip"
}

package_xcframework() {
    xcodebuild -create-xcframework \
        -framework "$BUILD_DIR/$FRAMEWORK_NAME.framework" \
        -output "$BUILD_DIR/$FRAMEWORK_NAME.xcframework" >/dev/null

    (
        cd "$BUILD_DIR"
        zip -q -r --symlinks "$FRAMEWORK_NAME.xcframework.zip" "$FRAMEWORK_NAME.xcframework"
    )
}

main() {
    cd "$ROOT_DIR"

    require_command cargo
    require_command rustup
    require_command lipo
    require_command zip
    require_command xcodebuild
    require_command python3

    prepare_c_module
    build_static_libraries
    assemble_framework

    if [[ "$SKIP_SIGNING" != "1" ]]; then
        require_command security
        require_command codesign
        require_command xcrun
        read_secrets
        setup_signing_keychain
        sign_framework
        notarize_framework
    fi

    package_xcframework
}

main "$@"
