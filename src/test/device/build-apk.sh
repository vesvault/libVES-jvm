#!/bin/sh
# build-apk.sh -- the device-test APK, on the build host: the release .aar and its
# SBOM as ./gradlew sbom makes them, this app around the .aar, and fresh fixtures.
#
#   VES_TEST_API=... VES_TEST_POLL=... sh src/test/device/build-apk.sh
#
# Then, with a phone on adb:
#   adb install -r libVES-jvm-device-test.apk
#   adb shell am start -n com.vesvault.libves.devicetest/.MainActivity
#   adb logcat -s libves-test
#   adb uninstall com.vesvault.libves.devicetest
# or copy the APK to the phone and open it. The results are on its screen, over
# the lock screen if the phone is locked, and it holds the screen on until closed.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
export ANDROID_HOME=${ANDROID_HOME:-/opt/android-sdk}

"$ROOT/gradlew" -p "$ROOT" --no-daemon -q sbom
A=$HERE/src/main/assets/fixtures
rm -rf "$A"
sh "$HERE/fixtures.sh" "$A"
# What the test compares the running libraries with.
V=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/build.gradle.kts")
node -e '
const bom = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
for (const c of bom.components[0].components) {
    if (c.name.endsWith(".so")) console.log(c.hashes[0].content + "  " + c.name);
}' "$ROOT/build/outputs/sbom/libVES-jvm-$V.cdx.json" > "$A/sbom-sha256.txt"
[ -s "$A/sbom-sha256.txt" ]
"$ROOT/gradlew" -p "$HERE" --no-daemon -q assembleDebug
APK=$HERE/build/outputs/apk/debug/libves-jvm-device-test-debug.apk
[ -f "$APK" ] || APK=$HERE/build/outputs/apk/debug/$(ls "$HERE/build/outputs/apk/debug" | grep '\.apk$' | head -1)
ls -l "$APK"
sha256sum "$APK"
