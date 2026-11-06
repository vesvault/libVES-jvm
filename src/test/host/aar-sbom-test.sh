#!/bin/bash
# aar-sbom-test.sh -- etc/aar-sbom.js accepts the .aar it describes, and
# refuses one that differs from build-inputs.json in each way it checks.
#
#   bash src/test/host/aar-sbom-test.sh [AAR]
#
# On the build host, after ./gradlew assembleRelease: needs the .aar, the
# prebuilts under src/main/cpp/deps, node and python3. Each case changes a
# scratch clone (committed, so the clone is clean) or a copy of the .aar;
# the checkout itself is not touched.
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
AAR=${1:-$ROOT/build/outputs/aar/libves-jvm-release.aar}
DEPS=$ROOT/src/main/cpp/deps
W=$(mktemp -d "${TMPDIR:-/var/tmp}/aar-sbom-test.XXXXXX") || exit 1
trap 'rm -rf "$W"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
no() { fail=$((fail + 1)); echo "FAIL $*"; }

R=$W/repo
git -c init.defaultBranch=master clone -q "$ROOT" "$R" || exit 1
git -C "$R" config submodule.libVES.c.url "$ROOT/libVES.c"
git -C "$R" -c init.defaultBranch=master -c protocol.file.allow=always submodule -q update --init || exit 1
git -C "$R" config user.name aar-sbom-test
git -C "$R" config user.email aar-sbom-test@invalid
base=$(git -C "$R" rev-parse HEAD)

reset() { git -C "$R" reset -q --hard "$base" && cp "$AAR" "$W/in.aar"; }
# The .aar is copied after any commit, so it is never older than the commit.
run() {
    cp "$W/in.aar" "$W/x.aar"
    node "$R/etc/aar-sbom.js" --deps "$DEPS" "$W/x.aar" > "$W/out" 2> "$W/err"
}
# edit JS: change build-inputs.json (j = the file, c(name) = a component), then commit
edit() {
    node -e 'const fs = require("fs"), f = process.argv[1], j = JSON.parse(fs.readFileSync(f, "utf8"));
        const c = (n) => j.components.find((x) => x.name === n);
        '"$1"';
        fs.writeFileSync(f, JSON.stringify(j, null, 2) + "\n");' "$R/build-inputs.json" &&
    git -C "$R" commit -q -am "test: $1"
}
refuses() {   # LABEL REGEX: the generator must fail, saying REGEX, and write nothing
    if run; then no "$1: accepted"
    elif [ -s "$W/out" ]; then no "$1: failed but wrote output"
    elif grep -qE "$2" "$W/err"; then ok "$1"
    else no "$1: $(head -3 "$W/err")"
    fi
}
# zipedit PY: rewrite $W/in.aar; PY sees z (entries: name -> bytes, in order)
zipedit() {
    python3 -I - "$W/in.aar" "$1" << 'EOF'
import sys, zipfile, io
path, code = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(path) as zf:
    z = {i.filename: zf.read(i) for i in zf.infolist()}
exec(code)
with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
    for n, b in z.items():
        zf.writestr(n, b)
EOF
}

# What build-inputs.json says now, so the cases below follow a version change.
# inp EXPR: evaluate EXPR with j = the file and c(name) = a component
inp() {
    node -e 'const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
        const c = (n) => j.components.find((x) => x.name === n);
        const w = (cs) => cs.flatMap((x) => [x.name].concat(w(x.components || [])));
        console.log('"$1"')' "$ROOT/build-inputs.json"
}
VES_VER=$(inp 'c("libVES.c").version')
CURL_VER=$(inp 'c("curl").header.value')
CURL_PFX=$(inp 'c("curl").marker.replace(/\.[0-9]+$/, "")')
FIRST_KEM=$(inp '[...c("liboqs").kems].sort()[0]')
NAMES=$(inp 'w(j.components).join(" ")')

# ---- accepted
reset
if run; then
    ok "the .aar as built"
    cp "$W/out" "$W/first"
    run && cmp -s "$W/out" "$W/first" && ok "a second run writes the same bytes" || no "a second run differs"
    want=$(sha256sum < "$AAR" | cut -c1-64)
    got=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).components[0].hashes[0].content)' "$W/first")
    [ "$got" = "$want" ] && ok "the SBOM names the .aar's SHA-256" || no "the SBOM says $got, the .aar is $want"
    node "$R/etc/aar-sbom.js" --deps "$DEPS" --out "$W/o/sbom.json" "$W/x.aar" && cmp -s "$W/o/sbom.json" "$W/first" &&
        ok "--out writes the same bytes" || no "--out differs from stdout"
    names=$(node -e 'const b = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); const w = (cs) => cs.flatMap((c) => [c.name].concat(w(c.components || [])));
        console.log(w(b.components.filter((c) => c.type !== "file")).join(" "))' "$W/first")
    [ "$names" = "$NAMES" ] &&
        ok "components: $names" || no "components: $names"
else
    no "the .aar as built: $(cat "$W/err")"
fi

# ---- the checkout
reset; echo >> "$R/README.md"
refuses "a changed tracked file" 'the checkout has changes'
reset; edit 'c("libVES.c").commit = "0".repeat(40)'
refuses "another libVES.c commit" 'submodule is pinned at'
reset; edit 'c("libVES.c").version = "0.0"'
refuses "another libVES.c version" "libVES.h says $VES_VER"

# ---- the components
reset; edit 'c("openssl").prebuilt["openssl/arm64-v8a/lib/libssl.a"] = "0".repeat(64)'
refuses "a prebuilt with another hash" 'the prebuilt openssl/arm64-v8a/lib/libssl.a is'
reset; edit 'c("curl").header.value = "0.0.0"'
refuses "a header with another version" "defines LIBCURL_VERSION as $CURL_VER, not 0.0.0"
reset; edit 'c("openssl").marker = "OpenSSL 0.0.0 1 Jan 1970"'
refuses "a version string libVES.so lacks" 'does not carry "OpenSSL 0.0.0'
reset; edit 'c("curl").marker = c("curl").marker.replace(/\.[0-9]+$/, "")'
refuses "a version string only the start of one in libVES.so" "does not carry \"$CURL_PFX\""
reset; edit 'c("liboqs").kems = c("liboqs").kems.slice(1)'
refuses "one KEM fewer" "libVES.so exports the KEMs $FIRST_KEM"
reset; edit 'j.platform = j.platform.filter((p) => p !== "libz.so")'
refuses "a platform library not listed" 'libVES.so needs libz.so'
reset; edit 'j.toolchain.comment[0] += " (another build)"'
refuses "another compiler" 'from a toolchain build-inputs.json does not name'

# ---- the .aar
reset; zipedit 'z["libs/extra.jar"] = b"x"'
refuses "an entry not described" 'holds libs/extra.jar'
reset; zipedit 'del z["jni/arm64-v8a/libVESjni.so"]'
refuses "a missing library" 'has no jni/arm64-v8a/libVESjni.so'
reset; zipedit '
src = io.BytesIO(z["classes.jar"]); out = io.BytesIO()
with zipfile.ZipFile(src) as a, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as b:
    for i in a.infolist(): b.writestr(i, a.read(i))
    b.writestr("org/example/Shaded.class", b"\xca\xfe\xba\xbe")
z["classes.jar"] = out.getvalue()'
refuses "a class from another package" 'not com.vesvault.libves: org/example/Shaded.class'
reset; python3 -I - "$W/in.aar" << 'EOF'
import sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p) as zf:
    i = zf.getinfo("jni/arm64-v8a/libVES.so")
with open(p, "r+b") as f:
    f.seek(i.header_offset + 26); n = int.from_bytes(f.read(2), "little"); x = int.from_bytes(f.read(2), "little")
    at = i.header_offset + 30 + n + x + 100000
    f.seek(at); b = f.read(1); f.seek(at); f.write(bytes([b[0] ^ 0x55]))
EOF
refuses "a corrupted library" 'does not (match its size or CRC|inflate)'

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
