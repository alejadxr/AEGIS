#!/bin/bash
# Build the AEGIS agent and copy it to the Tauri binaries directory
# with the correct platform-specific naming convention.
#
# Usage: ./build.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TAURI_BIN_DIR="$SCRIPT_DIR/../desktop-tauri/src-tauri/binaries"

echo "=== AEGIS Agent Build ==="
echo "Script dir: $SCRIPT_DIR"

# Ensure PyInstaller is installed
pip install pyinstaller 2>/dev/null || pip3 install pyinstaller 2>/dev/null

# Build the agent
cd "$SCRIPT_DIR"
python build_agent.py

# Determine the Rust target triple
TARGET_TRIPLE=$(rustc -Vv 2>/dev/null | grep 'host:' | awk '{print $2}')
if [ -z "$TARGET_TRIPLE" ]; then
    echo "WARNING: rustc not found, defaulting to x86_64-apple-darwin"
    TARGET_TRIPLE="x86_64-apple-darwin"
fi

# Create binaries directory if needed
mkdir -p "$TAURI_BIN_DIR"

# Copy with platform-specific name
BINARY_NAME="aegis-agent-${TARGET_TRIPLE}"
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    BINARY_NAME="${BINARY_NAME}.exe"
    cp "dist/aegis-agent.exe" "$TAURI_BIN_DIR/$BINARY_NAME"
else
    cp "dist/aegis-agent" "$TAURI_BIN_DIR/$BINARY_NAME"
fi

echo ""
echo "=== Build Complete ==="
echo "Binary: $TAURI_BIN_DIR/$BINARY_NAME"
echo "Target: $TARGET_TRIPLE"
ls -lh "$TAURI_BIN_DIR/$BINARY_NAME"
