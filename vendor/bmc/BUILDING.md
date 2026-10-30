# Building the bmc-node addon

`bmc-core` (vendored) + `bmc-node` (napi binding) → `server/native/bmc.<platform>-<arch>.node`.
The runtime loader (`server/src/bmc.js`) picks `bmc.<platform>-<arch>.node` first,
`bmc.node` as fallback — so a package can ship every built variant at once.

One command per platform from the repo root: `scripts/build-bmc-node.sh [linux|win32|darwin]`.

## Linux (here)

```sh
./scripts/build-bmc-node.sh linux   # → bmc.linux-x64.node (+ bmc.node)
```

Needs just cargo/rustup. This is what the dev tree uses.

## Windows — cross from Linux

```sh
rustup target add x86_64-pc-windows-gnu
apt install gcc-mingw-w64-x86-64
./scripts/build-bmc-node.sh win32   # → bmc.win32-x64.node
```

- `napi-build` needs a `libnode.dll` to link against; neither node.exe nor
  electron.exe ships one (node is statically linked). The script generates a
  stub DLL exporting the addon's `napi_*` imports (read from the linux `.so`)
  and points `LIBNODE_PATH` at it. Symbols resolve in-process at runtime.
  A prebuilt stub lives at `vendor/bmc/libnode-win/`.
- Vendored OpenSSL + ring compile fine under mingw (this is what Avocent's
  cipher-list workaround needs).

## macOS — must run on a Mac (VM or hardware)

You can't realistically cross-compile for `*-apple-darwin` from Linux
(needs the macOS SDK; osxcross is legally gray). Use the macOS VM.

```sh
# on the mac: xcode-select --install; install rustup
rustup target add aarch64-apple-darwin x86_64-apple-darwin
./scripts/build-bmc-node.sh darwin  # → bmc.darwin-universal.node (lipo)
```

- Builds both arch slices and `lipo`s them into one universal `.node`.
- native-tls → Security.framework; vendored OpenSSL builds for Avocent
  (needs Perl in PATH).
- SSH agent via `SSH_AUTH_SOCK` — already supported.

## Electron app packaging

`desktop/` scripts: `dist` (win NSIS), `dist:mac` (dmg/zip), `dist:linux`.
`prepare-standalone.js` copies `server/` wholesale — whatever
`server/native/bmc.*.node` files exist ship in the package and the loader
picks the right one at runtime. So: build every platform's `.node` first,
then package for whoever.

- **Windows installer on Linux** works here: needs `wine` + `wine32:i386`
  (multiarch) for the NSIS uninstaller step + rcedit icon stamping. Unsigned —
  `win.signAndEditExecutable` controls rcedit/signing; sign with Azure
  Trusted Signing / cert later via `signtoolOptions` or a `sign` hook.
- **macOS installer must build on the Mac** (`npm run dist:mac` in `desktop/`)
  — DMG creation + codesign/notarize are macOS-only steps.
