#!/bin/sh
# fixtures.sh DIR -- what DeviceTest reads: keys and items the ves CLI makes (on
# the build host, so an x86-64 CLI with liboqs 0.13 against the device's arm64
# libraries with 0.16), a current CA bundle, and a CA that signed nothing. The
# keys are throwaway: fresh on each run, and only ever open each other's test
# data. The APK carries them; do not reuse it for anything else.
#
# VES_TEST_API and VES_TEST_POLL name the test API the app talks to. There is no
# default, and the production URLs are refused: the test creates vaults.
set -eu
d=$1
VES=${VES:-/usr/local/bin/ves}
CA=${CA:-/etc/ssl/certs/ca-certificates.crt}
: "${VES_TEST_API:?set VES_TEST_API to a test API URL}"
: "${VES_TEST_POLL:?set VES_TEST_POLL to the long-poll URL of that API}"
case "$VES_TEST_API $VES_TEST_POLL" in
    *api.ves.host*|*poll.ves.host*) echo "fixtures.sh: that is production: the test creates vaults" >&2; exit 2 ;;
esac
mkdir -p "$d"
printf '%s\n' "$VES_TEST_API" > "$d/api.url"
printf '%s\n' "$VES_TEST_POLL" > "$d/poll.url"
head -c 44 /dev/urandom > "$d/key.raw"
pair() {   # NAME ALGO: a key, and an item wrapping key.raw for it
    "$VES" -g -G "$2" -ypf "$d/$1.priv" -Ypf "$d/$1.pub"
    "$VES" -Yf "$d/$1.pub" -G "${2%%:*}" -if "$d/key.raw" -Ipf "$d/$1.item"
}
pair mlkem768 OQS:ML-KEM-768
pair mlkem512 OQS:ML-KEM-512
pair mlkem1024 OQS:ML-KEM-1024
pair kyber768 OQS:Kyber768
# One whose public key ends in a zero byte, on purpose: libVES.c up to 1.37 cannot
# read those back, and about a quarter of sntrup761's do. Not left to chance.
i=0
while :; do
    pair sntrup761 OQS:sntrup761
    last=$(sed '/-----/d' "$d/sntrup761.pub" | tr -d '\n' | base64 -d | tail -c 1 | od -An -tu1 | tr -d ' ')
    [ "$last" = 0 ] && break
    i=$((i + 1))
    [ "$i" -lt 200 ] || { echo "fixtures.sh: no sntrup761 public key ending in zero in 200 tries" >&2; exit 2; }
done
pair bike OQS:BIKE-L1
pair p256 ECDH:prime256v1
pair p521 ECDH:secp521r1
pair k256 ECDH:secp256k1
pair rsa RSA:2048
head -c 24 /dev/urandom | base64 > "$d/enc.vk"
"$VES" -g -v "$(cat "$d/enc.vk")" -ypf "$d/enc.priv" -Ypf "$d/enc.pub"
grep -q ENCRYPTED "$d/enc.priv"
"$VES" -Yf "$d/enc.pub" -G OQS -if "$d/key.raw" -Ipf "$d/enc.item"
cp "$CA" "$d/cacert.pem"
openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -days 30 \
    -subj '/CN=libVES-jvm device test: signed nothing' -out "$d/wrong-ca.pem" 2> /dev/null
