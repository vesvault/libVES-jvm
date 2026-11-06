#!/bin/sh
# host-test.sh -- DeviceTest's checks on the build host, to find a bug in the test
# before anyone reaches for a phone. It does not test the arm64 libraries: the JNI
# is built against the host's libVES.c (LIBVES, default /usr/src/libVES.c) with the
# host's OpenSSL, libcurl and liboqs. Creates vaults on the test API's demo domain.
#
#   VES_TEST_API=... VES_TEST_POLL=... sh src/test/device/host-test.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
CPP=$ROOT/src/main/cpp
LIB=$ROOT/src/main/java/com/vesvault/libves
LIBVES=${LIBVES:-/usr/src/libVES.c}
JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}
ANN=${ANN:-$(find "$HOME/.gradle/caches" -name 'annotations-*.jar' 2>/dev/null | sort | tail -1)}
T=$(mktemp -d "${TMPDIR:-/tmp}/device-host-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
fail() { echo "device host-test: $*" >&2; exit 2; }
[ -n "$ANN" ] && [ -r "$ANN" ] || fail "no JetBrains annotations jar (ANN)"

echo "== fixtures"
sh "$HERE/fixtures.sh" "$T/data" || fail "fixtures.sh"
echo "== the JNI library, against $LIBVES"
CF="-fPIC -O1 -I$JAVA_HOME/include -I$JAVA_HOME/include/linux -I$CPP/include -I$LIBVES/lib -DHAVE_LIBOQS"
cc $CF -shared -o "$T/libVESjni.so" "$CPP/jni_libves.c" "$CPP/jni_util.c" "$CPP/jni_jvar.c" \
  "$CPP/jni_vault.c" "$CPP/jni_item.c" "$CPP/jni_itemcipher.c" "$CPP/jni_watch.c" "$CPP/jni_offlinekey.c" \
  "$CPP/tls_root.c" -L"$LIBVES/lib/.libs" -lVES -Wl,-rpath,"$LIBVES/lib/.libs" -lcurl -lcrypto 2> "$T/cc.err" \
  || { cat "$T/cc.err" >&2; fail "the JNI library does not compile or link"; }
echo "== the Java"
mkdir -p "$T/classes"
"$JAVA_HOME/bin/javac" -nowarn -cp "$ANN" -d "$T/classes" "$LIB"/*.java \
  "$HERE/src/main/java/com/vesvault/libves/devicetest/DeviceTest.java" "$HERE/host/HostMain.java" || fail "javac"
echo "== DeviceTest, on this host"
"$JAVA_HOME/bin/java" -Djava.library.path="$T" -cp "$T/classes:$ANN" \
  com.vesvault.libves.devicetest.HostMain "$T/data"
