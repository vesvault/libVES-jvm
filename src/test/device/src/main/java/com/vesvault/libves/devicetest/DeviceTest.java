/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves.devicetest;

import com.vesvault.libves.ErrorCode;
import com.vesvault.libves.Event;
import com.vesvault.libves.ItemCipher;
import com.vesvault.libves.OfflineKey;
import com.vesvault.libves.VESException;
import com.vesvault.libves.Vault;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * What the release .aar has to do on a real device, with its own native
 * libraries: load, open keys the ves CLI made, refuse TLS it cannot verify,
 * and work against a real VES API: a test one, named at build time, on its demo domain.
 *
 * No Android classes here, so host-test.sh runs the same checks on the build
 * host first, against the host's libraries. Only the device run tests the arm64
 * OpenSSL, libcurl and liboqs. The checks that hold only there are marked: the
 * host's libcurl has system CA roots, and its liboqs has BIKE.
 */
final class DeviceTest {
    interface Out { void line(String s); }

    /** Never the default, which is production: this creates vaults. fixtures.sh writes them. */
    String api;
    String poll;
    static final String DOM = "demo";
    /** Keys and items the ves CLI made (fixtures.sh). */
    static final String[] ALGS = {"mlkem768", "mlkem512", "mlkem1024", "kyber768", "sntrup761", "p256", "p521", "k256", "rsa"};

    final File dir;
    final Out out;
    final boolean device;
    final String nativeLibDir;
    int pass, fail;
    String ca;

    DeviceTest(File dir, Out out, boolean device, String nativeLibDir) {
        this.dir = dir;
        this.out = out;
        this.device = device;
        this.nativeLibDir = nativeLibDir;
    }

    void t(String label, boolean ok) {
        if (ok) pass++; else fail++;
        out.line((ok ? "PASS  " : "FAIL  ") + label);
    }

    /** The exception, with libVES's detail (for a failed connection, the curl error). */
    static String why(Throwable e) {
        String d = e instanceof VESException ? ((VESException) e).detail : null;
        return e + (d == null ? "" : " [" + d + "]");
    }

    byte[] bytes(String name) throws IOException { return read(new File(dir, name)); }
    String text(String name) throws IOException { return new String(bytes(name), StandardCharsets.UTF_8); }

    static byte[] read(File f) throws IOException {
        try (FileInputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            for (int n; (n = in.read(buf)) > 0;) b.write(buf, 0, n);
            return b.toByteArray();
        }
    }
    static String der(String pem) {
        return pem == null ? "" : pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
    }
    static String rnd() {
        String a = "abcdefghjkmnpqrstuvwxyz23456789";
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) sb.append(a.charAt(r.nextInt(a.length())));
        return sb.toString();
    }

    /** Runs everything; returns the number of failures. */
    int run() {
        try {
            api = text("api.url").trim();
            poll = text("poll.url").trim();
        } catch (IOException e) {
            t("the fixtures name no test API: " + e, false);
            return report();
        }
        out.line("-- native libraries");
        try {
            Vault.init("libVES-jvm-device-test");
            t("L1 libVESjni.so and libVES.so load, every symbol resolved", true);
        } catch (Throwable e) {
            t("L1 the native libraries do not load: " + why(e), false);
            return report();
        }
        try {
            sbomHashes();
            out.line("-- keys the ves CLI made, no network");
            offline();
            out.line("-- TLS: the same request to stage, only the CA differs");
            tls();
            out.line("-- against the test API");
            online();
        } catch (Exception e) {
            t("the test itself stopped: " + why(e), false);
        }
        return report();
    }

    int report() {
        out.line("");
        out.line("libVES-jvm device test: " + pass + " passed, " + fail + " failed");
        return fail;
    }

    /** The libraries running here are the ones the SBOM describes, byte for byte. */
    void sbomHashes() throws Exception {
        if (!device) return;
        for (String line : text("sbom-sha256.txt").split("\n")) {
            String[] p = line.trim().split("\\s+");
            if (p.length != 2) continue;
            File so = new File(nativeLibDir, new File(p[1]).getName());
            if (!so.exists()) {
                t("L2 " + so.getName() + " is not unpacked at " + nativeLibDir, false);
                continue;
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : MessageDigest.getInstance("SHA-256").digest(read(so))) hex.append(String.format("%02x", b));
            t("L2 " + so.getName() + " is the SBOM's (" + hex.substring(0, 12) + "...)", hex.toString().equals(p[0]));
        }
    }

    void offline() throws IOException {
        byte[] key = bytes("key.raw");
        for (String alg : ALGS) {
            try (OfflineKey k = OfflineKey.fromPEM(text(alg + ".priv"))) {
                t("O1 " + alg + ": the item decrypts to the bytes it wraps", Arrays.equals(k.decrypt(text(alg + ".item")), key));
                t("O1 " + alg + ": the public key is the one the CLI printed", der(k.publicKeyPEM()).equals(der(text(alg + ".pub"))));
            } catch (VESException e) {
                t("O1 " + alg + ": " + why(e), false);
            }
        }
        try (OfflineKey k = OfflineKey.fromPEM(text("p256.priv"))) {
            k.decrypt(text("mlkem768.item"));
            t("O2 another key's item: refused", false);
        } catch (VESException e) {
            t("O2 another key's item: refused", true);
        }
        try (OfflineKey k = OfflineKey.fromPEM(text("mlkem768.priv"))) {
            k.decrypt("not an item");
            t("O2 a ciphertext that is not one: refused", false);
        } catch (VESException e) {
            t("O2 a ciphertext that is not one: refused", true);
        }
        byte[] vk = text("enc.vk").trim().getBytes(StandardCharsets.UTF_8);
        try (OfflineKey k = OfflineKey.fromPEM(text("enc.priv"), vk)) {
            t("O3 an encrypted PEM with its VESkey: decrypts", Arrays.equals(k.decrypt(text("enc.item")), key));
        } catch (VESException e) {
            t("O3 an encrypted PEM with its VESkey: " + why(e), false);
        }
        try (OfflineKey k = OfflineKey.fromPEM(text("enc.priv"))) {
            t("O3 an encrypted PEM with no VESkey: refused", false);
        } catch (VESException e) {
            t("O3 an encrypted PEM with no VESkey: refused", true);
        }
        try (OfflineKey k = OfflineKey.fromPEM(text("enc.priv"), "wrong".getBytes(StandardCharsets.UTF_8))) {
            t("O3 an encrypted PEM with a wrong VESkey: refused", false);
        } catch (VESException e) {
            t("O3 an encrypted PEM with a wrong VESkey: refused", true);
        }
        if (device) {
            // The Android liboqs has no BIKE: an error, never a crash or a wrong answer.
            try (OfflineKey k = OfflineKey.fromPEM(text("bike.priv"))) {
                k.decrypt(text("bike.item"));
                t("O4 a KEM not compiled in (BIKE): refused", false);
            } catch (VESException e) {
                t("O4 a KEM not compiled in (BIKE): refused", true);
            }
        }
    }

    /** Asks about a vault nobody has, so nothing changes; the answer says if TLS got through. */
    ErrorCode probe(String bundle) {
        try (Vault v = new Vault("ves://" + DOM + "/!jvmprobe-" + rnd() + "/")) {
            v.setOption(Vault.Option.API_URL, api);
            if (bundle != null) v.setOption(Vault.Option.TLS_ROOT, new File(dir, bundle).getPath());
            v.unlock("not-a-veskey".getBytes(StandardCharsets.UTF_8));
            return ErrorCode.OK;
        } catch (VESException e) {
            return e.code;
        }
    }

    void tls() {
        ErrorCode c;
        if (device) {
            // Must come first: TLS_ROOT is process-wide and cannot be unset.
            c = probe(null);
            t("T1 no CA at all (none is compiled in): refused (" + c + ")", c == ErrorCode.CONN);
            // Only on the device: the host's libcurl also has a built-in CA path, which
            // CAINFO does not replace, so a wrong bundle still verifies there.
            c = probe("wrong-ca.pem");
            t("T2 a CA that did not sign stage: refused (" + c + ")", c == ErrorCode.CONN);
        }
        c = probe("cacert.pem");
        t("T3 the CA bundle: stage answers, no such vault (" + c + ")", c == ErrorCode.NOT_FOUND);
        ca = new File(dir, "cacert.pem").getPath();
    }

    Vault open(String uri) throws VESException {
        return new Vault(uri).setOption(Vault.Option.API_URL, api).setOption(Vault.Option.TLS_ROOT, ca);
    }

    void online() throws Exception {
        String tag = rnd();
        String name = "!jvmdev-" + tag, adm = "!jvmdevadm-" + tag;
        String uri = "ves://" + DOM + "/" + name + "/", admUri = "ves://" + DOM + "/" + adm + "/";
        String item = "ves://" + DOM + "/jvmdev-" + tag + ".txt";
        String line = "device test " + tag;
        byte[] vk = null, admVk = null;
        String pub = null, priv = null;
        out.line("(vaults //" + DOM + "/" + name + "/ and //" + DOM + "/" + adm + "/)");

        try (Vault v = open(uri)) {
            vk = v.createAnonymous();
            pub = v.publicKeyPEM();
            priv = v.privateKeyPEM();
            t("C1 a new vault: a VESkey, a key pair made here", vk != null && vk.length >= 16
              && pub != null && pub.contains("PUBLIC KEY") && priv.contains("PRIVATE KEY") && !priv.contains("ENCRYPTED"));
        } catch (VESException e) {
            t("C1 createAnonymous: " + why(e), false);
        }
        try (Vault v = open(uri)) {
            v.createAnonymous();
            t("C2 the same name again: refused", false);
        } catch (VESException e) {
            t("C2 the same name again: refused, DENIED", e.code == ErrorCode.DENIED);
        }
        try (Vault a = open(admUri)) {
            admVk = a.createAnonymous();
            t("C3 a second vault", admVk != null);
        } catch (VESException e) {
            t("C3 a second vault: " + why(e), false);
        }
        if (vk == null || admVk == null) return;

        try (Vault v = open(uri).unlock(vk)) {
            t("C4 opened again with the VESkey: unlocked, a session, the same key",
              v.unlocked() && v.sessionToken() != null && der(v.publicKeyPEM()).equals(der(pub)));
            v.item(item).put(line, Arrays.asList(uri, admUri));
            t("C5 an item put, shared with both vaults", true);
        } catch (VESException e) {
            t("C4/C5 " + why(e), false);
        }
        try (Vault a = open(admUri).unlock(admVk)) {
            t("C6 the other vault reads it", line.equals(a.item(item).getString()));
        } catch (VESException e) {
            t("C6 " + why(e), false);
        }
        try (OfflineKey k = OfflineKey.fromPEM(priv)) {
            t("C7 the exported private key loads offline, same public key", der(k.publicKeyPEM()).equals(der(pub)));
        } catch (VESException e) {
            t("C7 " + why(e), false);
        }
        cipher(uri, vk, tag);
        watch(uri, vk, admUri, admVk, tag);
    }

    /** A megabyte through the item cipher, in two chunks, and back. */
    void cipher(String uri, byte[] vk, String tag) {
        String item = "ves://" + DOM + "/jvmdev-" + tag + ".bin";
        byte[] plain = new byte[1 << 20];
        new SecureRandom().nextBytes(plain);
        try (Vault v = open(uri).unlock(vk)) {
            ByteArrayOutputStream enc = new ByteArrayOutputStream();
            long t0 = System.nanoTime();
            try (ItemCipher c = v.item(item).cipher(null, Arrays.asList(uri))) {
                enc.write(c.encrypt(Arrays.copyOfRange(plain, 0, 300000), false));
                enc.write(c.encrypt(Arrays.copyOfRange(plain, 300000, plain.length), true));
            }
            long ms = (System.nanoTime() - t0) / 1000000;
            byte[] ct = enc.toByteArray();
            try (ItemCipher d = v.item(item).cipher()) {
                t("C8 1 MB through the item cipher and back (" + ms + " ms with the API calls)",
                  Arrays.equals(d.decrypt(ct, true), plain));
            }
            // Bad input to a failing decrypt: an exception, never a crash or the plaintext.
            byte[] flipped = ct.clone();
            flipped[ct.length / 2] ^= 1;
            damaged(v, item, "a flipped bit", flipped, plain);
            damaged(v, item, "cut in half", Arrays.copyOf(ct, ct.length / 2), plain);
            damaged(v, item, "random bytes", rndBytes(4096), plain);
            damaged(v, item, "nothing", new byte[0], plain);
        } catch (Exception e) {
            t("C8 " + why(e), false);
        }
    }

    void damaged(Vault v, String item, String label, byte[] ct, byte[] plain) throws VESException {
        try (ItemCipher d = v.item(item).cipher()) {
            byte[] back = d.decrypt(ct, true);
            t("C9 ciphertext damaged, " + label + ": not the data", !Arrays.equals(back, plain));
        } catch (VESException e) {
            if (e.code != ErrorCode.CRYPTO) throw e;
            t("C9 ciphertext damaged, " + label + ": refused", true);
        }
    }

    static byte[] rndBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    /** The long-poll: an event arrives, and stop() breaks a poll in flight. */
    void watch(String uri, byte[] vk, String admUri, byte[] admVk, String tag) throws Exception {
        final CountDownLatch got = new CountDownLatch(1);
        final Exception[] err = new Exception[1];
        class W extends Vault {
            W() throws VESException { super(uri); }
            @Override protected void onEvent(Event e) { got.countDown(); }
            @Override protected void onError(Exception e) { err[0] = e; }
        }
        try (W w = new W()) {
            w.setOption(Vault.Option.API_URL, api).setOption(Vault.Option.POLL_URL, poll).setOption(Vault.Option.TLS_ROOT, ca);
            w.unlock(vk);
            w.pollSeconds(20);
            w.start();
            Thread.sleep(2000);
            try (Vault a = open(admUri).unlock(admVk)) {
                a.item("ves://" + DOM + "/jvmdev-" + tag + ".watch").put("event", Arrays.asList(uri, admUri));
            }
            t("W1 an item shared with the vault arrives as an event", got.await(30, TimeUnit.SECONDS));
            Thread.sleep(1500);
            long t0 = System.nanoTime();
            w.stop();
            w.join();
            long ms = (System.nanoTime() - t0) / 1000000;
            t("W2 stop() breaks a long-poll in flight (" + ms + " ms)", ms < 5000);
            t("W3 no poll error" + (err[0] == null ? "" : ": " + err[0]), err[0] == null);
        } catch (VESException e) {
            t("W1 " + why(e), false);
        }
    }
}
