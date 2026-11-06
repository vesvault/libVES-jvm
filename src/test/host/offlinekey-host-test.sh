#!/bin/sh
# Host test for OfflineKey: the JNI file built
# against the host libVES, driven from a real JVM, on keys and items the ves
# CLI made. No device, no emulator, no network.
#
#   sh src/test/host/offlinekey-host-test.sh     exit 0 only if every check passes
#
# Needs: a JDK (JAVA_HOME), a built libVES.c (LIBVES, its lib/.libs/libVES.so
# and headers), the ves CLI (VES), the JetBrains annotations jar (ANN; found
# in the Gradle cache if not given). The Android build compiles the same
# jni_offlinekey.c against the pinned libVES.c submodule; the calls it makes
# (libVES_VaultKey_new with autoPEM, libVES_VaultKey_decrypt) are the same
# in both (2026-10-09: KeyAlgo_EVP.c and VaultKey.c identical, KeyAlgo_OQS.c
# differing only in build-time checks).
#
# The Java runs under `unshare -rn` when it can, a network namespace with
# nothing in it, so a key that tried the VES API would fail rather than pass.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
CPP=$ROOT/src/main/cpp
LIB=$ROOT/src/main/java/com/vesvault/libves
LIBVES=${LIBVES:-/usr/src/libVES.c}
VES=${VES:-/usr/local/bin/ves}
JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}
ANN=${ANN:-$(find "$HOME/.gradle/caches" -name 'annotations-*.jar' 2>/dev/null | sort | tail -1)}
T=$(mktemp -d "${TMPDIR:-/tmp}/offlinekey-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
fail() { echo "offlinekey-host-test: $*" >&2; exit 2; }
[ -n "$ANN" ] && [ -r "$ANN" ] || fail "no JetBrains annotations jar (ANN)"

echo "== the JNI library, against $LIBVES"
CF="-fPIC -O1 -I$JAVA_HOME/include -I$JAVA_HOME/include/linux -I$CPP/include -I$LIBVES/lib -DHAVE_LIBOQS"
# This file warning-free on its own; the rest as they are.
cc $CF -Wall -Wextra -Werror -c -o "$T/jni_offlinekey.o" "$CPP/jni_offlinekey.c" || fail "jni_offlinekey.c does not compile cleanly"
cc $CF -shared -o "$T/libVESjni.so" "$CPP/jni_libves.c" "$CPP/jni_util.c" "$CPP/jni_jvar.c" "$T/jni_offlinekey.o" \
  -L"$LIBVES/lib/.libs" -lVES -Wl,-rpath,"$LIBVES/lib/.libs" -lcrypto || fail "the JNI library does not link"

echo "== the Java"
mkdir -p "$T/classes"
"$JAVA_HOME/bin/javac" -cp "$ANN" -d "$T/classes" "$LIB/OfflineKey.java" "$LIB/VESException.java" "$LIB/ErrorCode.java" \
  "$HERE/OfflineKeyHostTest.java" || fail "javac"

echo "== keys and items, made by $($VES -V | head -1)"
d=$T/data; mkdir -p "$d"
head -c 44 /dev/urandom > "$d/key.raw"
"$VES" -g -ypf "$d/oqs.priv" -Ypf "$d/oqs.pub" || fail "ves -g (OQS)"
"$VES" -g -G ECDH:prime256v1 -ypf "$d/ec.priv" -Ypf "$d/ec.pub" || fail "ves -g (ECDH)"
"$VES" -g -G RSA:2048 -ypf "$d/rsa.priv" -Ypf "$d/rsa.pub" || fail "ves -g (RSA)"
head -c 24 /dev/urandom | base64 > "$d/enc.vk"
"$VES" -g -v "$(cat "$d/enc.vk")" -ypf "$d/enc.priv" -Ypf "$d/enc.pub" || fail "ves -g -v (encrypted)"
grep -q 'ENCRYPTED' "$d/enc.priv" || fail "ves -g -v did not encrypt the PEM"
for a in oqs:OQS ec:ECDH rsa:RSA enc:OQS; do
  "$VES" -Yf "$d/${a%%:*}.pub" -G "${a#*:}" -if "$d/key.raw" -Ipf "$d/${a%%:*}.item" || fail "ves -Y (${a%%:*})"
done

echo "== OfflineKey, from Java"
RUN="$JAVA_HOME/bin/java -Djava.library.path=$T -cp $T/classes:$ANN OfflineKeyHostTest $d"
if unshare -rn true 2>/dev/null; then
  echo "(in a network namespace with nothing in it)"
  unshare -rn $RUN
else
  echo "(unshare -rn is not allowed here: with the network)"
  $RUN
fi
