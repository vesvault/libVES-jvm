# libVES-jvm

[![CI](https://github.com/vesvault/libVES-jvm/actions/workflows/ci.yml/badge.svg)](https://github.com/vesvault/libVES-jvm/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Java/Kotlin bindings for [libVES.c](https://github.com/vesvault/libVES.c), the C
implementation of the VES encrypted key exchange library.

The Java API is modeled on `libVES.subtle()` from
[libVES.js](https://github.com/vesvault/libVES):

- `com.vesvault.libves.Vault`
- `com.vesvault.libves.Item`
- `com.vesvault.libves.ItemCipher`

Packages as an Android `.aar`. JNI shims live under `src/main/cpp/`; libVES.c
is vendored as a submodule and built via Gradle's `externalNativeBuild`.

## Building

1. Clone with submodules:
   ```sh
   git clone --recurse-submodules https://github.com/vesvault/libVES-jvm.git
   ```
2. Static prebuilts for OpenSSL, libcurl, and liboqs are not in the repo.
   Provide them under `src/main/cpp/deps/<lib>/<abi>/` (headers in `include/`,
   static libs in `lib/`), or point `src/main/cpp/deps` at an existing tree:
   ```sh
   ln -s /path/to/prebuilt/deps src/main/cpp/deps
   ```
3. Build:
   ```sh
   ./gradlew assembleRelease
   ```

## Continuous integration

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) compiles
the Java API and syntax-checks the JNI shim against the libVES.c submodule
headers on every push and pull request. The full native `assembleRelease` links
against static prebuilts for OpenSSL, libcurl, and liboqs that are not public,
so it is not run in CI — that build is validated on the build host.

## Status

JNI bindings implemented for `Vault`, `Item`, `ItemCipher`, `VESFlow`, and
`VESLocker` (wrapping the corresponding `libVES_*` / `VESlocker_*` / `VESflow_*`
calls). `assembleRelease` builds a clean `.aar` on the build host (2026-07-05):
both `libVES.so` (from the submodule) and `libVESjni.so` compile, link, and
bundle for `arm64-v8a`, with **no** undefined libVES-API symbols (every symbol
the shim references is provided by the bundled `libVES.so` — verified with
`llvm-nm -u`, despite `LOCAL_ALLOW_UNDEFINED_SYMBOLS`).

Not yet verified: runtime behavior against the live VES API (auth flow, item
read, share/unshare) — needs a device/emulator run or a host-target JNI build.
