/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
import com.vesvault.libves.OfflineKey;
import com.vesvault.libves.VESException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Host test for {@link OfflineKey} (offlinekey-host-test.sh builds the JNI
 * library against the host libVES and makes the keys and items with the ves
 * CLI): each key algorithm decrypts what `ves -Y KEY -i DATA` made for it, and
 * every way of not being able to is an exception, never a wrong answer.
 */
public class OfflineKeyHostTest {
    static int pass, fail;
    static String dir;

    static void t(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  PASS  " + label); }
        else    { fail++; System.out.println("  FAIL  " + label); }
    }
    static String text(String name) throws Exception {
        return new String(Files.readAllBytes(Paths.get(dir, name)), StandardCharsets.UTF_8);
    }
    static byte[] bytes(String name) throws Exception {
        return Files.readAllBytes(Paths.get(dir, name));
    }
    static String der(String pem) {
        return pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
    }

    public static void main(String[] args) throws Exception {
        dir = args[0];
        byte[] key = bytes("key.raw");

        for (String alg : new String[] {"oqs", "ec", "rsa"}) {
            try (OfflineKey k = OfflineKey.fromPEM(text(alg + ".priv"))) {
                t(alg + ": the item ves made decrypts to the bytes it wraps",
                  Arrays.equals(k.decrypt(text(alg + ".item")), key));
                String pub = k.publicKeyPEM();
                t(alg + ": its public key is the one ves printed",
                  pub != null && der(pub).equals(der(text(alg + ".pub"))));
            } catch (VESException e) {
                t(alg + ": " + e, false);
            }
        }

        try (OfflineKey k = OfflineKey.fromPEM(text("ec.priv"))) {
            k.decrypt(text("oqs.item"));
            t("another key's item: refused", false);
        } catch (VESException e) {
            t("another key's item: refused (VESException)", true);
        }

        try (OfflineKey k = OfflineKey.fromPEM(text("oqs.priv"))) {
            k.decrypt("not an item");
            t("a ciphertext that is not one: refused", false);
        } catch (VESException e) {
            t("a ciphertext that is not one: refused (VESException)", true);
        }

        byte[] vk = new String(bytes("enc.vk"), StandardCharsets.UTF_8).trim().getBytes(StandardCharsets.UTF_8);
        try (OfflineKey k = OfflineKey.fromPEM(text("enc.priv"), vk)) {
            t("a PEM encrypted with a VESkey, given it: decrypts",
              Arrays.equals(k.decrypt(text("enc.item")), key));
        } catch (VESException e) {
            t("a PEM encrypted with a VESkey, given it: " + e, false);
        }
        try (OfflineKey k = OfflineKey.fromPEM(text("enc.priv"))) {
            t("an encrypted PEM without its VESkey: refused", false);
        } catch (VESException e) {
            t("an encrypted PEM without its VESkey: refused (VESException)", true);
        }
        try (OfflineKey k = OfflineKey.fromPEM(text("enc.priv"), "wrong".getBytes(StandardCharsets.UTF_8))) {
            t("an encrypted PEM with a wrong VESkey: refused", false);
        } catch (VESException e) {
            t("an encrypted PEM with a wrong VESkey: refused (VESException)", true);
        }
        try (OfflineKey k = OfflineKey.fromPEM("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")) {
            t("a PEM that is not a key: refused", false);
        } catch (VESException e) {
            t("a PEM that is not a key: refused (VESException)", true);
        }

        OfflineKey k = OfflineKey.fromPEM(text("oqs.priv"));
        k.close();
        try {
            k.decrypt(text("oqs.item"));
            t("used after close: refused", false);
        } catch (IllegalStateException e) {
            t("used after close: refused (IllegalStateException)", true);
        }
        k.close();
        t("closed twice: no crash", true);

        System.out.println("OfflineKey host test: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
