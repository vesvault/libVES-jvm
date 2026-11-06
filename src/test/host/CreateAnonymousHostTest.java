/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
import com.vesvault.libves.ErrorCode;
import com.vesvault.libves.OfflineKey;
import com.vesvault.libves.VESException;
import com.vesvault.libves.Vault;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;

/**
 * Host test for {@link Vault#createAnonymous()} against a real VES API
 * (createanonymous-host-test.sh: a test API, the demo domain). It does what
 * an app does when it enrols itself with no login: create its anonymous
 * vault, open it again with the VESkey, and put an item shared with its own
 * vault and an admin vault. The script then checks the result with the ves CLI.
 *
 * args: apiUrl domain outDir
 */
public class CreateAnonymousHostTest {
    static int pass, fail;

    static void t(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  PASS  " + label); }
        else    { fail++; System.out.println("  FAIL  " + label); }
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
    static Vault open(String api, String uri) throws VESException {
        return new Vault(uri).setOption(Vault.Option.API_URL, api);
    }
    static void write(String dir, String name, byte[] b) throws Exception {
        Files.write(Paths.get(dir, name), b);
    }

    public static void main(String[] args) throws Exception {
        String api = args[0], dom = args[1], out = args[2];
        Vault.init("libVES-jvm-host-test");
        String tag = rnd();
        String name = "!jvmtest-" + tag, adm = "!jvmadm-" + tag;
        String uri = "ves://" + dom + "/" + name + "/", admUri = "ves://" + dom + "/" + adm + "/";
        String item = "ves://" + dom + "/jvmtest-" + tag + ".ssh";
        String line = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDIh" + tag;
        byte[] vk = null, admVk = null;
        String pub = null, priv = null;

        try (Vault v = open(api, uri)) {
            vk = v.createAnonymous();
            t("C1 " + name + " created: a VESkey back", vk != null && vk.length >= 16);
            pub = v.publicKeyPEM();
            priv = v.privateKeyPEM();
            t("C1 ...its public key at once", pub != null && pub.contains("PUBLIC KEY"));
            t("C1 ...its private key at once, plain PEM", priv.contains("PRIVATE KEY") && !priv.contains("ENCRYPTED"));
        } catch (VESException e) {
            t("C1 createAnonymous: " + e, false);
        }

        try (Vault v = open(api, uri)) {
            v.createAnonymous();
            t("C2 the same name again: refused", false);
        } catch (VESException e) {
            t("C2 the same name again: refused, DENIED", e.code == ErrorCode.DENIED);
            // VES refuses too ("Access denied", measured 2026-10-09 with the
            // local check removed); the local check refuses before any POST.
            t("C2 ...by the local check, before any POST (" + e.getMessage() + ")",
              String.valueOf(e.getMessage()).contains("exists already"));
        }
        try (Vault v = open(api, uri)) {
            t("C2 ...the vault's key unchanged", pub != null && der(v.publicKeyPEM()).equals(der(pub)));
        } catch (VESException e) {
            t("C2 ...the vault's key: " + e, false);
        }

        try (Vault v = open(api, "ves://" + dom + "/jvmtest-" + tag + "/")) {
            v.createAnonymous();
            t("C3 no '!': refused", false);
        } catch (VESException e) {
            t("C3 no '!': refused, PARAM", e.code == ErrorCode.PARAM);
        }

        try (Vault a = open(api, admUri)) {
            admVk = a.createAnonymous();
            t("C4 the admin vault " + adm + " created", admVk != null);
        } catch (VESException e) {
            t("C4 admin vault: " + e, false);
        }

        if (vk != null && admVk != null) {
            try (Vault v = open(api, uri).unlock(vk)) {
                t("C5 opened again with the VESkey: unlocked, a session", v.unlocked() && v.sessionToken() != null);
                t("C5 ...the same public key", der(v.publicKeyPEM()).equals(der(pub)));
                v.item(item).put(line, List.of(uri, admUri));
                t("C6 the item put, shared with its own vault and the admin vault", true);
            } catch (VESException e) {
                t("C5/C6 " + e, false);
            }
            try (Vault a = open(api, admUri).unlock(admVk)) {
                t("C7 the admin vault reads it", line.equals(a.item(item).getString()));
            } catch (VESException e) {
                t("C7 " + e, false);
            }
        }

        if (priv != null) {
            try (OfflineKey k = OfflineKey.fromPEM(priv)) {
                t("C8 the exported private key loads offline; same public key", der(k.publicKeyPEM()).equals(der(pub)));
            } catch (VESException e) {
                t("C8 " + e, false);
            }
        }

        write(out, "name", name.getBytes(StandardCharsets.UTF_8));
        write(out, "adm", adm.getBytes(StandardCharsets.UTF_8));
        write(out, "item", item.getBytes(StandardCharsets.UTF_8));
        write(out, "line", line.getBytes(StandardCharsets.UTF_8));
        if (vk != null) write(out, "vk", vk);
        if (admVk != null) write(out, "adm.vk", admVk);
        if (pub != null) write(out, "pub.pem", pub.getBytes(StandardCharsets.UTF_8));
        if (priv != null) write(out, "priv.pem", priv.getBytes(StandardCharsets.UTF_8));

        System.out.println("java: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
