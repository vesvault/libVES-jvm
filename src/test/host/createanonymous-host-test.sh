#!/bin/sh
# Host test for Vault.createAnonymous(): the JNI
# library built against the host libVES, driven from a real JVM, against a
# real VES API -- a test one, the demo domain, where the CLI suite keeps its test
# vaults. Then the ves CLI reads back what the Java made, the way an admin's
# tools would read an enrolled app's vault:
#   - the vault's public key and algorithm, with no login (-k ... -Ypf, -Gp);
#   - the item, through the admin vault it is shared with (-a ... -o ... -ip);
#   - a cipher key wrapped for that public key (-Y), unwrapped with the
#     private key the Java exported (-y), as the phone does offline.
#
#   VES_API_URL=... sh src/test/host/createanonymous-host-test.sh   exit 0 only if every check passes
#
# Needs what offlinekey-host-test.sh needs, plus the network. VES_API_URL names
# the test API; it is never left to the default, which is production.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
CPP=$ROOT/src/main/cpp
LIB=$ROOT/src/main/java/com/vesvault/libves
LIBVES=${LIBVES:-/usr/src/libVES.c}
VES=${VES:-/usr/local/bin/ves}
API=${VES_API_URL:?set VES_API_URL to a test API URL: this test creates vaults}
DOM=${VES_TEST_DOMAIN:-demo}
JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}
ANN=${ANN:-$(find "$HOME/.gradle/caches" -name 'annotations-*.jar' 2>/dev/null | sort | tail -1)}
T=$(mktemp -d "${TMPDIR:-/tmp}/createanon-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
fail() { echo "createanonymous-host-test: $*" >&2; exit 2; }
[ -n "$ANN" ] && [ -r "$ANN" ] || fail "no JetBrains annotations jar (ANN)"
case $API in *stage*|*sbx*|*localhost*) ;; *) fail "VES_API_URL=$API is not a test API: this test creates vaults" ;; esac
vesc() { "$VES" "--api-url=$API" "$@"; }

echo "== the JNI library, against $LIBVES"
CF="-fPIC -O1 -I$JAVA_HOME/include -I$JAVA_HOME/include/linux -I$CPP/include -I$LIBVES/lib -DHAVE_LIBOQS"
cc $CF -shared -o "$T/libVESjni.so" "$CPP/jni_libves.c" "$CPP/jni_util.c" "$CPP/jni_jvar.c" \
  "$CPP/jni_vault.c" "$CPP/jni_item.c" "$CPP/jni_itemcipher.c" "$CPP/jni_watch.c" "$CPP/jni_offlinekey.c" \
  "$CPP/tls_root.c" -L"$LIBVES/lib/.libs" -lVES -Wl,-rpath,"$LIBVES/lib/.libs" -lcurl -lcrypto 2> "$T/cc.err" \
  || { cat "$T/cc.err" >&2; fail "the JNI library does not compile or link"; }
# The new function warning-free on its own.
grep -n 'nativeCreateAnonymous' "$T/cc.err" >&2 && fail "jni_vault.c: warnings in nativeCreateAnonymous"

echo "== the Java"
mkdir -p "$T/classes"
"$JAVA_HOME/bin/javac" -cp "$ANN" -d "$T/classes" "$LIB"/*.java "$HERE/CreateAnonymousHostTest.java" || fail "javac"

echo "== Vault.createAnonymous, from Java, against $API, domain $DOM"
d=$T/data; mkdir -p "$d"
"$JAVA_HOME/bin/java" -Djava.library.path="$T" -cp "$T/classes:$ANN" CreateAnonymousHostTest "$API" "$DOM" "$d"
jrc=$?

echo "== read back with $($VES -V | head -1)"
pass=0; nfail=0
t() { l=$1; shift; if "$@" >/dev/null 2>&1; then pass=$((pass+1)); echo "  PASS  $l"; else nfail=$((nfail+1)); echo "  FAIL  $l"; fi; }
der() { sed '/-----/d' "$1" | tr -d '\r\n'; }
name=$(cat "$d/name" 2>/dev/null); adm=$(cat "$d/adm" 2>/dev/null); item=$(cat "$d/item" 2>/dev/null); item=//${item#ves://}
# A file the Java did not write is a failure, never two empty strings that match.
line=$(cat "$d/line" 2>/dev/null); [ -n "$line" ] || line="(the Java wrote none)"
vesc -k "//$DOM/$name/" -Ypf "$d/cli.pub" >/dev/null 2>&1
a=$(der "$d/cli.pub" 2>/dev/null); b=$(der "$d/pub.pem" 2>/dev/null); [ -n "$a" ] || a=none
t "V1 the CLI fetches the vault's public key with no login: the one Java has" [ "$a" = "$b" ]
algo=$(vesc -k "//$DOM/$name/" -Gp 2>/dev/null | head -1)
t "V2 ...and its algorithm: OQS ($algo)" [ "$algo" = OQS ]
got=$(vesc -a "//$DOM/$adm/" -uf "$d/adm.vk" -o "$item" -ip 2>/dev/null)
t "V3 the CLI reads the item through the admin vault" [ "$got" = "$line" ]
got=$(vesc -a "//$DOM/$name/" -uf "$d/vk" -o "$item" -ip 2>/dev/null)
t "V4 ...and through the vault's own VESkey" [ "$got" = "$line" ]
head -c 44 /dev/urandom > "$d/k"
"$VES" -Yf "$d/cli.pub" -G OQS -if "$d/k" -Ipf "$d/wrapped" 2>/dev/null
"$VES" -yf "$d/priv.pem" -If "$d/wrapped" -ipf "$d/k2" 2>/dev/null
t "V5 a key wrapped offline for the fetched public key unwraps with the exported private key" cmp -s "$d/k" "$d/k2"

echo "createanonymous host test: java rc $jrc; cli $pass passed, $nfail failed"
[ "$jrc" = 0 ] && [ "$nfail" = 0 ]
