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

## SBOM

A release publishes a CycloneDX 1.6 SBOM, `libVES-jvm-<version>.cdx.json`,
next to the `.aar`. A scanner reading the `.aar` finds nothing in it: there
are no Java dependencies, and the third-party code is C compiled into
`jni/arm64-v8a/libVES.so`, which is libVES.c plus OpenSSL, libcurl and liboqs
from the static prebuilts. [`build-inputs.json`](build-inputs.json) pins each
of them: version, commit, source archive hash, the prebuilt archives' hashes
and build options.

```sh
./gradlew sbom
```

runs `assembleRelease`, then `etc/aar-sbom.js` (needs Node), which writes
`build/outputs/sbom/libVES-jvm-<version>.cdx.json` from that file after
checking the file against the `.aar`.
Each library's version string must be in `libVES.so`, the prebuilts must be
the pinned ones, liboqs must export exactly the KEMs listed, the native
libraries may link only each other and Android system libraries, and
`classes.jar` may hold only `com.vesvault.libves`. Any mismatch stops it.
The output carries no timestamp, so the same `.aar` gives the same SBOM.

## Status

JNI bindings implemented for `Vault`, `Item`, `ItemCipher`, `VESFlow`, and
`VESLocker` (wrapping the corresponding `libVES_*` / `VESlocker_*` / `VESflow_*`
calls). `assembleRelease` builds a clean `.aar` on the build host (2026-07-05):
both `libVES.so` (from the submodule) and `libVESjni.so` compile, link, and
bundle for `arm64-v8a`, with **no** undefined libVES-API symbols (every symbol
the shim references is provided by the bundled `libVES.so` — verified with
`llvm-nm -u`, despite `LOCAL_ALLOW_UNDEFINED_SYMBOLS`).

On a real device (see "Device test"): loading, keys, TLS, anonymous vaults,
items, sharing, the item cipher and the event watch. Not yet run on a device:
the login flows (`VESFlow`, `VESLocker`).

## Device test

`src/test/device/` is a small app around the release `.aar` itself, so what runs
is what the SBOM describes. On launch it checks, on its screen and in logcat (tag
`libves-test`), that the native libraries load and their SHA-256 are the SBOM's;
that keys and items the `ves` CLI made open, with the refusals; that TLS is refused
with no CA and with a wrong one and works with the right one; and, on a test API,
vaults, items, the item cipher with damaged ciphertext, and the long-poll.

```sh
VES_TEST_API=... VES_TEST_POLL=... sh src/test/device/host-test.sh   # the same checks, host libraries
VES_TEST_API=... VES_TEST_POLL=... sh src/test/device/build-apk.sh   # the APK
```

The URLs have no default, since the test creates vaults. The app shows itself over
the lock screen because behind a locked screen Android 15 blocks an app's network
a few seconds in (`blocked=APP_BACKGROUND`), which looks like a libcurl failure.

2026-11-05 on a moto g power 5G (2024), Android 15, with libVES.c 1.38: 45 of 45.
The fixtures draw a sntrup761 key whose public key ends in a zero byte on purpose,
since libVES.c up to 1.37 cannot read those back.

## Offline keys

`OfflineKey` holds a vault key as PEM and uses it with no `Vault` and no
network: `OfflineKey.fromPEM(pem[, veskey]).decrypt(itemCiphertext)` decrypts an
item encrypted to its public key, as `ves -Y KEY -i DATA` makes it and
`ves -y KEY -I DATA` reads it. RSA and EC keys go through EVP, OQS (ML-KEM)
keys through liboqs, chosen from the PEM (`autoPEM`). Its libVES context points
the API at `offline://no-network/`, as the CLI's offline mode does.
`Vault.privateKeyPEM()` exports an unlocked vault key's private key for such a
copy, and `Vault.publicKeyPEM()` its public key. It is for an app that has to
unwrap a cipher key while the VES API is unreachable.

**Host test** (no device): `sh src/test/host/offlinekey-host-test.sh` on the
build host compiles the JNI file against the host libVES.c, makes keys and
items with the `ves` CLI, and drives `OfflineKey` from a JVM inside a network
namespace with nothing in it. 2026-10-09: 14/14 (OQS, EC, RSA; an encrypted
PEM with and without its VESkey; another key's item, garbage, a non-key PEM,
use after close).
