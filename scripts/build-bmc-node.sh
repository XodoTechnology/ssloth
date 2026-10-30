#!/usr/bin/env bash
# Build the bmc-node napi addon (vendored bmc-core) for the platforms that
# matter, and lay the result down in server/native/.
#
#   ./scripts/build-bmc-node.sh            # this host's platform
#   ./scripts/build-bmc-node.sh win32      # cross-build Windows (mingw)
#   ./scripts/build-bmc-node.sh darwin     # macOS universal (run on a Mac)
#
# Output: server/native/bmc.<platform>-<arch>.node — the loader in
# server/src/bmc.js prefers the platform-named file and falls back to
# bmc.node, so any built artifacts here ride along in every package.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
VENDOR=$ROOT/vendor/bmc
NATIVE=$ROOT/server/native
mkdir -p "$NATIVE"

want=${1:-$(node -p "process.platform === 'linux' ? 'linux' : process.platform === 'win32' ? 'win32' : 'darwin'" 2>/dev/null || uname -s | tr 'A-Z' 'a-z')}

case "$want" in
  linux)
    cargo build --release -p bmc-node --manifest-path "$VENDOR/Cargo.toml"
    cp "$VENDOR/target/release/libbmc_node.so" "$NATIVE/bmc.linux-x64.node"
    cp "$NATIVE/bmc.linux-x64.node" "$NATIVE/bmc.node"   # dev-tree convenience
    ;;
  win32)
    # Needs: rustup target add x86_64-pc-windows-gnu, gcc-mingw-w64-x86-64.
    # napi-build wants libnode.dll for the link — Electron/Node don't ship
    # it, so a stub DLL exporting the napi_* symbols stands in (the real
    # symbols resolve inside node.exe/electron.exe at runtime).
    export LIBNODE_PATH="${LIBNODE_PATH:-$ROOT/vendor/bmc/libnode-win}"
    if [ ! -f "$LIBNODE_PATH/libnode.dll" ]; then
      mkdir -p "$LIBNODE_PATH"
      # Make sure a linux build exists so we can read its undefined napi_*.
      cargo build --release -p bmc-node --manifest-path "$VENDOR/Cargo.toml"
      nm -D "$VENDOR/target/release/libbmc_node.so" \
        | awk '$2=="U"&&$NF~/^napi/{print "  "$NF" = _stub"}' > "$LIBNODE_PATH/libnode.exports"
      { echo 'LIBRARY libnode.dll'; echo 'EXPORTS'; cat "$LIBNODE_PATH/libnode.exports"; } > "$LIBNODE_PATH/libnode.def"
      echo 'void _stub(void){}' > "$LIBNODE_PATH/stub.c"
      x86_64-w64-mingw32-gcc -shared -o "$LIBNODE_PATH/libnode.dll" \
        "$LIBNODE_PATH/stub.c" "$LIBNODE_PATH/libnode.def"
    fi
    mkdir -p "$VENDOR/.cargo"
    printf '[target.x86_64-pc-windows-gnu]\nlinker = "x86_64-w64-mingw32-gcc"\n' > "$VENDOR/.cargo/config.toml"
    cargo build --release -p bmc-node --manifest-path "$VENDOR/Cargo.toml" --target x86_64-pc-windows-gnu
    cp "$VENDOR/target/x86_64-pc-windows-gnu/release/bmc_node.dll" "$NATIVE/bmc.win32-x64.node"
    ;;
  darwin)
    # Run ON a Mac (VM or hardware). Xcode CLT + rustup targets:
    #   rustup target add aarch64-apple-darwin x86_64-apple-darwin
    # Universal .node via lipo, same trick upstream uses for its dmg.
    cargo build --release -p bmc-node --manifest-path "$VENDOR/Cargo.toml" --target aarch64-apple-darwin
    cargo build --release -p bmc-node --manifest-path "$VENDOR/Cargo.toml" --target x86_64-apple-darwin
    lipo -create \
      "$VENDOR/target/aarch64-apple-darwin/release/libbmc_node.dylib" \
      "$VENDOR/target/x86_64-apple-darwin/release/libbmc_node.dylib" \
      -output "$NATIVE/bmc.darwin-universal.node"
    ;;
  *)
    echo "unknown target: $want (linux | win32 | darwin)" >&2
    exit 1
    ;;
esac
ls -la "$NATIVE"/bmc*.node
