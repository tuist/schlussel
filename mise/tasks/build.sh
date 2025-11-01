#!/usr/bin/env bash
set -euo pipefail

# Cross-platform build script for Schlussel
# Builds static and shared libraries for common platforms

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/dist"

echo "Building Schlussel for multiple platforms..."
echo "============================================"
echo ""

# Clean previous builds
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Define target platforms
# Format: "zig-target:output-dir"
TARGETS=(
    "x86_64-linux-gnu:linux-x86_64"
    "aarch64-linux-gnu:linux-aarch64"
    "x86_64-macos:macos-x86_64"
    "aarch64-macos:macos-aarch64"
    "x86_64-windows-gnu:windows-x86_64"
    "aarch64-windows-gnu:windows-aarch64"
)

build_for_target() {
    local target=$1
    local output_dir=$2

    echo "Building for $output_dir (target: $target)..."

    local target_dir="$BUILD_DIR/$output_dir"
    mkdir -p "$target_dir"

    # Build static library
    zig build -Dtarget="$target" -Doptimize=ReleaseSafe --prefix "$target_dir"

    if [ $? -eq 0 ]; then
        echo "  ✓ Build successful for $output_dir"

        # List generated files
        echo "  Generated files:"
        find "$target_dir" -type f | sed 's|^|    |'
    else
        echo "  ✗ Build failed for $output_dir"
        return 1
    fi

    echo ""
}

# Build for each target
for target_spec in "${TARGETS[@]}"; do
    IFS=':' read -r target output_dir <<< "$target_spec"
    build_for_target "$target" "$output_dir" || echo "Warning: Build failed for $output_dir"
done

echo "============================================"
echo "Cross-platform build complete!"
echo ""
echo "Build artifacts are in: $BUILD_DIR"
echo ""
echo "Directory structure:"
tree -L 2 "$BUILD_DIR" 2>/dev/null || find "$BUILD_DIR" -type f | head -20

echo ""
echo "To use the library:"
echo "  - Include: include/schlussel.h"
echo "  - Link against the appropriate library for your platform"
echo ""
