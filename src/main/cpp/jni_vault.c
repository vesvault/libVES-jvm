/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * jni_vault.c: native methods for com.vesvault.libves.Vault.
 ***************************************************************************/
#include "jni_util.h"
#include "jVar.h"
#include "libVES.h"
#include "libVES/List.h"
#include "libVES/Ref.h"
#include "libVES/REST.h"
#include "libVES/User.h"
#include "libVES/Util.h"
#include "libVES/VaultItem.h"
#include "libVES/VaultKey.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libVES_init() stores the app-name POINTER without copying it (libVES.c), and
 * every REST request's User-Agent header dereferences it (REST.c). The JNI
 * string is only valid until ReleaseStringUTFChars, so passing it straight to
 * libVES_init leaves a dangling pointer — the User-Agent then carries freed
 * memory, which intermittently corrupts the header and breaks requests
 * (observed as HTTP/2 PROTOCOL_ERROR -> "Communication with the API server
 * failed"). Keep a persistent strdup and free the previous one only after
 * libVES has adopted the new pointer. A null app is a no-op in libVES_init, so
 * leave any existing name in place. */
static char *vesjni_appName = NULL;

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeInit(JNIEnv *env, jclass cls, jstring japp) {
    (void) cls;
    if (!japp) { libVES_init(NULL); return; }
    const char *app = (*env)->GetStringUTFChars(env, japp, NULL);
    if (!app) return;
    char *dup = strdup(app);
    (*env)->ReleaseStringUTFChars(env, japp, app);
    if (!dup) return;
    libVES_init(dup);
    free(vesjni_appName);
    vesjni_appName = dup;
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Vault_nativeNew(JNIEnv *env, jclass cls, jstring juri) {
    (void) cls;
    if (!juri) {
        vesjni_throw(env, LIBVES_E_PARAM, "Vault URI is null", NULL);
        return 0;
    }
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES *ves = NULL;
    /* Two URI shapes:
     *   ves://domain/extId         — app vault by external ref (libVES_new path)
     *   ves:////userRef            — primary vault by userRef (typically email)
     *
     * libVES_Ref_fromURI handles the first directly; on the second it returns
     * NULL but advances `uri` past the parsed scheme so `*uri == '/'` means we
     * landed at the userRef. libVES_VaultKey_listFromURI uses the same trick
     * for the primary VaultKey URI; we mirror it here so a Vault wrapping the
     * primary signup flow can be constructed up front without an external. */
    libVES_Ref *ref = libVES_Ref_fromURI(&uri, NULL);
    if (ref) {
        ves = libVES_fromRef(ref);
    } else if (*uri == '/') {
        uri++;
        libVES_User *user = libVES_User_fromPath(&uri);
        if (user) {
            ves = libVES_fromRef(NULL);
            if (ves) libVES_setUser(ves, user);
            /* setUser REFUPs when storing; this free is a no-op on a held
             * ref (REFBUSY) but frees the loose ref if setUser was a no-op
             * because ves->me was already populated. */
            libVES_User_free(user);
        }
    }
    if (!ves) vesjni_throw(env, LIBVES_E_PARAM, "Invalid vault URI", uri_orig);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    return (jlong) (intptr_t) ves;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeInitFn(JNIEnv *env, jclass cls, jlong h, jlong fnPtr) {
    (void) env; (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    void (*fn)(libVES *) = (void (*)(libVES *)) (intptr_t) fnPtr;
    if (ves && fn) fn(ves);
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Vault_nativeChild(JNIEnv *env, jclass cls, jlong h) {
    (void) env; (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    return (jlong) (intptr_t) libVES_child(ves);
}

/* Open a child Vault context targeted at a (domain, externalId) reference
 * without fetching the vault key. Used to prepare the context for
 * setVESkey-for-secondary — the secondary doesn't exist yet, so
 * nativeFetchVaultKey's GET path would 404. libVES_child clones the
 * parent's unlocked vaultKey via REFUP (so the child can elevate via
 * libVES_refreshSession against it). We replace the inherited external
 * (which on a primary-URI parent is NULL) with one parsed from this
 * (domain, externalId) so the eventual nativeSetVESkey can attach the
 * new key to the right external. */
JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Vault_nativeSubVault(JNIEnv *env, jclass cls, jlong h,
                                               jstring jdomain, jstring jext) {
    (void) cls;
    libVES *pves = (libVES *) (intptr_t) h;
    if (!pves) { vesjni_throw(env, LIBVES_E_PARAM, "Parent Vault is null", NULL); return 0; }
    if (!jdomain || !jext) {
        vesjni_throw(env, LIBVES_E_PARAM, "subVault: domain/externalId required", NULL);
        return 0;
    }
    libVES *child = libVES_child(pves);
    if (!child) { vesjni_throw(env, LIBVES_E_INTERNAL, "libVES_child failed", NULL); return 0; }
    const char *domain = (*env)->GetStringUTFChars(env, jdomain, NULL);
    const char *ext = (*env)->GetStringUTFChars(env, jext, NULL);
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "ves://%s/%s", domain, ext);
    (*env)->ReleaseStringUTFChars(env, jdomain, domain);
    (*env)->ReleaseStringUTFChars(env, jext, ext);
    if (n <= 0 || n >= (int) sizeof(buf)) {
        libVES_free(child);
        vesjni_throw(env, LIBVES_E_PARAM, "subVault: URI too long", NULL);
        return 0;
    }
    const char *p = buf;
    libVES_Ref *ref = libVES_Ref_fromURI(&p, NULL);
    if (!ref) {
        libVES_free(child);
        vesjni_throw(env, LIBVES_E_PARAM, "subVault: failed to parse ref", buf);
        return 0;
    }
    if (child->external) libVES_REFDN(Ref, child->external);
    /* libVES_Ref_fromURI returns a refct=0 ref (REFINIT). Match libVES_fromRef
     * by REFUPping when storing as ves->external — without this, the first
     * intermediate REFUP/REFDN cycle (e.g. new_vk->external in
     * libVES_VaultKey_post → libVES_VaultKey_free) walks the count to -1 and
     * frees the ref out from under us, leaving child->external dangling for
     * libVES_free to touch (heap corruption on close). */
    child->external = libVES_REFUP(Ref, ref);
    return (jlong) (intptr_t) child;
}

/* Fetch the vault key addressed by `uri` into the libVES context `h`,
 * without creating one if missing. Two URI shapes:
 *
 *   ves://domain/extId/[userRef]/  — secondary, fetched by ref via
 *                                    libVES_VaultKey_get2 with O_GET only
 *                                    (no O_NEW: don't mint a temp key).
 *   ves:////userRef/               — primary, resolved via the first entry
 *                                    of libVES_User_activeVaultKeys (also
 *                                    no creation path).
 *
 * libVES_VaultKey_fromURI / _listFromURI both pull in O_NEW or the
 * VaultKey_create fallback, which would silently mint a temp key on a
 * miss — wrong for a pure lookup. Dispatch explicitly here.
 *
 * Caller owns the returned key and must release via nativeFreeVaultKey.
 * Also plug the key into libves->vaultKey when that slot is empty —
 * subsequent libVES_unlock / _getVaultKey calls then have a current vault
 * key to operate on without an extra fetch. If the libVES already carries
 * an unlocked chain (which is what let the fetch decrypt a sub-key in the
 * first place), the chain stays; the returned sub-key is for the caller
 * to address explicitly via vaultKeyHandle. */
JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Vault_nativeFetchVaultKey(JNIEnv *env, jclass cls, jlong h, jstring juri) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    if (!juri) { vesjni_throw(env, LIBVES_E_PARAM, "Vault key URI is null", NULL); return 0; }
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES_Ref *ref = libVES_Ref_fromURI(&uri, ves);
    libVES_VaultKey *vk = NULL;
    if (ref) {
        /* Secondary by ref. GET only — no O_NEW means we get NULL on miss
         * (caller surfaces it as NOT_FOUND) rather than a fresh temp key. */
        vk = libVES_VaultKey_get2(ref, ves, NULL, NULL, LIBVES_O_GET);
        libVES_Ref_free(ref);
    } else if (*uri == '/') {
        /* Primary by userRef (ves:////userRef). Parse the userRef and ask
         * for the user's active vault keys; the first is the current
         * primary. activeVaultKeys never creates. */
        uri++;
        libVES_User *user = libVES_User_fromPath(&uri);
        if (user) {
            libVES_List *list = libVES_User_activeVaultKeys(user, NULL, ves);
            if (list) {
                if (list->len) {
                    /* Transfer the first slot to vk without REFUP — NULL it
                     * so List_free's freefn skips it (NULL-safe). */
                    vk = (libVES_VaultKey *) list->list[0];
                    list->list[0] = NULL;
                    /* activeVaultKeys's response carries id/type/algo/
                     * publicKey only — no user field — so vk->user is
                     * NULL. Plug in the path-parsed user (which already
                     * has the email) so a later libVES_VaultKey_getUser
                     * skips the vaultKeys/{id}?fields=user(...) lookup
                     * (sbx returns DENIED for unauthenticated callers)
                     * and goes straight to libVES_User_loadFields against
                     * the public users endpoint to populate the id. */
                    if (!vk->user) vk->user = libVES_REFUP(User, user);
                }
                libVES_List_free(list);
            }
            libVES_User_free(user);
        }
    } else {
        libVES_setError(ves, LIBVES_E_PARAM, "Vault URI expected (missing a trailing '/'?)");
    }
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vk) { vesjni_throw_from(env, ves); return 0; }
    if (!ves->vaultKey) ves->vaultKey = libVES_REFUP(VaultKey, vk);
    return (jlong) (intptr_t) vk;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeFreeVaultKey(JNIEnv *env, jclass cls, jlong h) {
    (void) env; (void) cls;
    libVES_VaultKey *vk = (libVES_VaultKey *) (intptr_t) h;
    libVES_VaultKey_free(vk);
}

/* Pick the vault key to operate on: explicit handle (child case) wins,
 * otherwise fall back to libVES_getVaultKey (root after unlock). */
static libVES_VaultKey *vesjni_pick_vk(libVES *ves, jlong vkh) {
    if (vkh) return (libVES_VaultKey *) (intptr_t) vkh;
    return ves ? libVES_getVaultKey(ves) : NULL;
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Vault_nativeVaultKeyId(JNIEnv *env, jclass cls, jlong h, jlong vkh) {
    (void) env; (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_VaultKey *vk = vesjni_pick_vk(ves, vkh);
    return (jlong) libVES_VaultKey_getId(vk);
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Vault_nativeUserId(JNIEnv *env, jclass cls, jlong h, jlong vkh) {
    (void) env; (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_VaultKey *vk = vesjni_pick_vk(ves, vkh);
    if (vk) {
        libVES_User *u = libVES_VaultKey_getUser(vk);
        if (u) return (jlong) libVES_User_getId(u);
    }
    /* Root before unlock with only a session token: libVES_me triggers the
     * /me lookup using the bearer token. */
    if (ves) {
        libVES_User *me = libVES_me(ves);
        if (me) return (jlong) libVES_User_getId(me);
    }
    return 0;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeSetSessionToken(JNIEnv *env, jclass cls, jlong h, jstring jtok) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    if (!ves) return;
    if (jtok) {
        const char *tok = (*env)->GetStringUTFChars(env, jtok, NULL);
        libVES_setSessionToken(ves, tok);
        (*env)->ReleaseStringUTFChars(env, jtok, tok);
    } else {
        libVES_setSessionToken(ves, NULL);
    }
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_Vault_nativeGetSessionToken(JNIEnv *env, jclass cls, jlong h) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    if (!ves) return NULL;
    const char *tok = libVES_getSessionToken(ves);
    return tok ? (*env)->NewStringUTF(env, tok) : NULL;
}

/* Wire codes for Vault.Option — MUST match the `code` field of the Java enum in
 * Vault.java. Deliberately distinct from the LIBVES_O_* ordinals so libVES.h can
 * be reordered without breaking the Java side. */
#define VESJNI_OPT_API_URL          1
#define VESJNI_OPT_WWW_URL          2
#define VESJNI_OPT_POLL_URL         3
#define VESJNI_OPT_APP_NAME         4
#define VESJNI_OPT_TLS_ROOT         5
#define VESJNI_OPT_DEBUG            6
#define VESJNI_OPT_VESKEY_LEN       7
#define VESJNI_OPT_SESSION_TIMEOUT  8

/* Map a Vault.Option wire code to its libVES_setOption() option number, or -1
 * for codes that are not plain libVES options (e.g. TLS_ROOT). */
static int vesjni_libves_optn(jint code) {
    switch (code) {
        case VESJNI_OPT_API_URL:         return LIBVES_O_APIURL;
        case VESJNI_OPT_WWW_URL:         return LIBVES_O_WWWURL;
        case VESJNI_OPT_POLL_URL:        return LIBVES_O_POLLURL;
        case VESJNI_OPT_APP_NAME:        return LIBVES_O_APPNAME;
        case VESJNI_OPT_DEBUG:           return LIBVES_O_DEBUG;
        case VESJNI_OPT_VESKEY_LEN:      return LIBVES_O_VESKEYLEN;
        case VESJNI_OPT_SESSION_TIMEOUT: return LIBVES_O_SESSTMOUT;
        default:                         return -1;
    }
}

/* Defined in tls_root.c (compiled into libVES.so so it can reach the
 * library-local curl symbols). Points the bundled libcurl at a PEM CA bundle so
 * the API TLS handshake verifies where libcurl has no system CA path. */
extern void vesjni_tlsroot_set(const char *path);
extern void vesjni_tlsroot_httpinit(libVES *ves);

/* Vault.setOption(Option, String). String-valued libVES options (API/WWW/POLL
 * URL, app name) are strdup'd to a process-lifetime copy because
 * libVES_setOption stores the pointer verbatim and never frees these fields
 * (the defaults are string literals) — a bounded, intentional per-set leak.
 * TLS_ROOT is not a libVES option: it stashes the CA path and installs the
 * httpInitFn that applies it before each REST request. */
JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeSetOptionStr(JNIEnv *env, jclass cls, jlong h, jint code, jstring jval) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    if (!ves || !jval) return;
    const char *val = (*env)->GetStringUTFChars(env, jval, NULL);
    if (val) {
        if (code == VESJNI_OPT_TLS_ROOT) {
            vesjni_tlsroot_set(val);
            libVES_setOption(ves, LIBVES_O_HTTPINITFN, (void *) &vesjni_tlsroot_httpinit);
        } else {
            int optn = vesjni_libves_optn(code);
            if (optn >= 0) libVES_setOption(ves, optn, (void *) strdup(val));
        }
        (*env)->ReleaseStringUTFChars(env, jval, val);
    }
}

/* Vault.setOption(Option, long). Scalar libVES options (DEBUG / VESKEYLEN /
 * SESSTMOUT), which libVES_setOption reads back as (long long) val. */
JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeSetOptionInt(JNIEnv *env, jclass cls, jlong h, jint code, jlong val) {
    (void) env; (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    if (!ves) return;
    int optn = vesjni_libves_optn(code);
    if (optn >= 0) libVES_setOption(ves, optn, (void *) (intptr_t) val);
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeUnlock(JNIEnv *env, jclass cls, jlong h, jbyteArray jvk) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    /* libVES_unlock_veskey has two branches:
     *  - libves->vaultKey set: unlock that key directly
     *  - libves->external NULL: use libVES_me + libVES_User_vaultKeys (fanout)
     * If we have an external but no vault key (common: Vault(uri) + session
     * token, nothing else), neither branch fires and unlock silently no-ops.
     * Fetch the primary first so the direct-unlock path is reachable. */
    if (!ves->vaultKey && ves->external) {
        libVES_VaultKey *pri = libVES_VaultKey_get(ves->external, ves, NULL);
        if (!pri) { vesjni_throw_from(env, ves); return; }
        /* REFUP when storing as the owned ves->vaultKey (mirrors
         * nativeFetchVaultKey). libVES_VaultKey_get returns the key at refct 0;
         * leaving it there means a later libVES_child REFUP + child teardown
         * REFDN frees it out from under this context (use-after-free in the
         * parent's libVES_free -> libVES_lock path when an event watch runs on
         * a child). */
        ves->vaultKey = libVES_REFUP(VaultKey, pri);
    }
    jsize klen = (*env)->GetArrayLength(env, jvk);
    char *vk = malloc((size_t) klen);
    if (!vk) {
        vesjni_throw(env, LIBVES_E_INTERNAL, "Out of memory", NULL);
        return;
    }
    (*env)->GetByteArrayRegion(env, jvk, 0, klen, (jbyte *) vk);
    int ok = libVES_unlock(ves, (size_t) klen, vk) != NULL;
    vesjni_wipe(vk, (size_t) klen);
    free(vk);
    if (!ok) vesjni_throw_from(env, ves);
}

JNIEXPORT jboolean JNICALL
Java_com_vesvault_libves_Vault_nativeUnlocked(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    return libVES_unlocked(ves) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeLock(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_lock(ves);
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeFree(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_free(ves);
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_Vault_nativeRandom(JNIEnv *env, jclass cls, jint length) {
    (void) cls;
    if (length <= 0) length = LIBVES_VESKEY_LEN;
    libVES_veskey *vk = libVES_veskey_generate((size_t) length);
    if (!vk) {
        vesjni_throw(env, LIBVES_E_INTERNAL, "veskey generation failed", NULL);
        return NULL;
    }
    /* Biased-ASCII content is 7-bit printable, safe as UTF-8.
     * Copy into a NUL-terminated scratch buffer for NewStringUTF. */
    char *buf = malloc((size_t) vk->keylen + 1);
    if (!buf) {
        libVES_veskey_free(vk);
        vesjni_throw(env, LIBVES_E_INTERNAL, "Out of memory", NULL);
        return NULL;
    }
    memcpy(buf, vk->veskey, vk->keylen);
    buf[vk->keylen] = 0;
    jstring s = (*env)->NewStringUTF(env, buf);
    vesjni_wipe(buf, vk->keylen);
    free(buf);
    libVES_veskey_free(vk);
    return s;
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_Vault_nativeDomain(JNIEnv *env, jclass cls, jlong h) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_Ref *ref = libVES_getExternal(ves);
    if (!ref) return NULL;
    const char *d = libVES_Ref_getDomain(ref);
    return d ? (*env)->NewStringUTF(env, d) : NULL;
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_Vault_nativeExternalId(JNIEnv *env, jclass cls, jlong h) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_Ref *ref = libVES_getExternal(ves);
    if (!ref) return NULL;
    const char *xid = libVES_Ref_getExternalId(ref);
    return xid ? (*env)->NewStringUTF(env, xid) : NULL;
}

/* Append a URI for an item or its associated vault key. Returns 1 if matched. */
static int append_item_uri(JNIEnv *env, jobjectArray result, jsize idx,
                            libVES_VaultItem *vi, int as_vault_key) {
    char *u = NULL;
    if (as_vault_key && vi->objectType == LIBVES_O_VKEY && vi->vaultKey) {
        u = libVES_VaultKey_toURI(vi->vaultKey);
    } else {
        u = libVES_VaultItem_toURI(vi);
        if (!u) u = libVES_VaultItem_toURIi(vi);
    }
    if (!u) return 0;
    jstring js = (*env)->NewStringUTF(env, u);
    (*env)->SetObjectArrayElement(env, result, idx, js);
    (*env)->DeleteLocalRef(env, js);
    free(u);
    return 1;
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Vault_nativePassword(JNIEnv *env, jclass cls, jlong h, jlong vkh) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_VaultKey *vk = vesjni_pick_vk(ves, vkh);
    if (!vk) { vesjni_throw_from(env, ves); return 0; }
    /* libVES_VaultKey_getVaultItem lazy-loads vkey->vitem via getPrivateKey
     * if it's not in memory yet — single round trip that pulls the vault key,
     * its password vitem (id + type + entries), and the user. The vitem comes
     * back without `value`; Item.get() will load+decrypt on first call. REFUP
     * before handing to Java so Item.close() can REFDN symmetrically. */
    libVES_VaultItem *vi = libVES_VaultKey_getVaultItem(vk);
    if (!vi) { vesjni_throw_from(env, ves); return 0; }
    return (jlong) (intptr_t) libVES_REFUP(VaultItem, vi);
}

JNIEXPORT jobjectArray JNICALL
Java_com_vesvault_libves_Vault_nativeChildVaults(JNIEnv *env, jclass cls, jlong h, jlong vkh) {
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_VaultKey *vk = vesjni_pick_vk(ves, vkh);
    if (!vk) { vesjni_throw_from(env, ves); return NULL; }
    libVES_List *list = libVES_VaultItem_list(vk);
    if (!list) { vesjni_throw_from(env, ves); return NULL; }
    /* Sub-vaults are PASSWORD items whose entry references a secondary vault
     * key. objectType==VKEY + type==PASSWORD matches the libVES.js objects()
     * filter shape. */
    jsize count = 0;
    for (size_t i = 0; i < list->len; i++) {
        libVES_VaultItem *vi = list->list[i];
        if (libVES_VaultItem_getType(vi) == LIBVES_VI_PASSWORD
            && vi->objectType == LIBVES_O_VKEY && vi->vaultKey) count++;
    }
    jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(JJ)V");
    if (!ctor) { libVES_List_free(list); return NULL; }
    jobjectArray result = (*env)->NewObjectArray(env, count, cls, NULL);
    if (!result) { libVES_List_free(list); return NULL; }
    jsize idx = 0;
    for (size_t i = 0; i < list->len; i++) {
        libVES_VaultItem *vi = list->list[i];
        if (libVES_VaultItem_getType(vi) != LIBVES_VI_PASSWORD
            || vi->objectType != LIBVES_O_VKEY || !vi->vaultKey) continue;
        libVES *child = libVES_child(ves);
        if (!child) continue;
        /* REFUP so the child Vault holds an owning ref even after the list
         * (which currently holds the vitem holding this vault key) is freed. */
        libVES_VaultKey *childvk = libVES_REFUP(VaultKey, vi->vaultKey);
        jobject obj = (*env)->NewObject(env, cls, ctor,
                                        (jlong) (intptr_t) child,
                                        (jlong) (intptr_t) childvk);
        if (!obj) {
            libVES_VaultKey_free(childvk);
            libVES_free(child);
            break;
        }
        (*env)->SetObjectArrayElement(env, result, idx++, obj);
        (*env)->DeleteLocalRef(env, obj);
    }
    libVES_List_free(list);
    return result;
}

JNIEXPORT jobjectArray JNICALL
Java_com_vesvault_libves_Vault_nativeItems(JNIEnv *env, jclass cls, jlong h) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_VaultKey *vk = libVES_getVaultKey(ves);
    if (!vk) {
        vesjni_throw_from(env, ves);
        return NULL;
    }
    libVES_List *list = libVES_VaultItem_list(vk);
    if (!list) {
        vesjni_throw_from(env, ves);
        return NULL;
    }
    jclass str_cls = (*env)->FindClass(env, "java/lang/String");
    jobjectArray result = (*env)->NewObjectArray(env, (jsize) list->len, str_cls, NULL);
    if (!result) {
        libVES_List_free(list);
        return NULL;
    }
    for (size_t i = 0; i < list->len; i++) {
        libVES_VaultItem *vi = list->list[i];
        char *u = libVES_VaultItem_toURI(vi);
        if (!u) u = libVES_VaultItem_toURIi(vi);
        if (u) {
            jstring js = (*env)->NewStringUTF(env, u);
            (*env)->SetObjectArrayElement(env, result, (jsize) i, js);
            (*env)->DeleteLocalRef(env, js);
            free(u);
        }
    }
    libVES_List_free(list);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_Vault_nativeUri(JNIEnv *env, jclass cls, jlong h) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    libVES_Ref *ref = libVES_getExternal(ves);
    if (!ref) return NULL;
    const char *domain = libVES_Ref_getDomain(ref);
    const char *xid = libVES_Ref_getExternalId(ref);
    if (domain && xid) {
        size_t need = 7 + strlen(domain) + 1 + strlen(xid) + 1;
        char *uri = malloc(need);
        if (!uri) return NULL;
        snprintf(uri, need, "ves://%s/%s", domain, xid);
        jstring s = (*env)->NewStringUTF(env, uri);
        free(uri);
        return s;
    }
    long long iid = libVES_Ref_getInternalId(ref);
    if (iid) {
        char buf[40];
        snprintf(buf, sizeof(buf), "ves:///%lld", iid);
        return (*env)->NewStringUTF(env, buf);
    }
    return NULL;
}

/* Wrap a Java byte[] into a heap libVES_veskey. Caller owns the result and
 * must wipe + libVES_veskey_free it; on allocation failure throws and
 * returns NULL. */
static libVES_veskey *vesjni_veskey_from_jba(JNIEnv *env, jbyteArray jvk) {
    jsize klen = (*env)->GetArrayLength(env, jvk);
    libVES_veskey *vk = libVES_veskey_new((size_t) klen, NULL);
    if (!vk) {
        vesjni_throw(env, LIBVES_E_INTERNAL, "Out of memory", NULL);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, jvk, 0, klen, (jbyte *) vk->veskey);
    return vk;
}

/* Create a new SECONDARY vault key for the app vault carried by this libVES
 * (ves->external), locked under the caller-supplied veskey, with its password
 * vault item shared to the active primary keys + propagators so the user can
 * recover the secondary's VESkey via primary unlock later.
 *
 * Mirrors libVES.js setSecondaryKey({...},veskey) — but the rekey-from-existing
 * branch is skipped: this is for the initial creation path, not rotation.
 * Requires the libVES instance to already be unlocked (or have a session token
 * + cached primary), since libVES_VaultKey_propagate calls
 * libVES_User_activeVaultKeys + encrypts the vitem against the returned
 * primary public keys.
 *
 * The veskey bytes are copied into a heap libVES_veskey for libVES_VaultKey_new
 * (which then copies into vitem->value); both buffers are wiped on the way out. */
JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeSetVESkey(JNIEnv *env, jclass cls, jlong h, jbyteArray jvk) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    if (!ves) {
        vesjni_throw(env, LIBVES_E_PARAM, "Vault is null", NULL);
        return;
    }
    if (!ves->external) {
        vesjni_throw(env, LIBVES_E_PARAM,
                     "setVESkey(veskey) requires the vault URI to carry an app vault external reference",
                     NULL);
        return;
    }
    if (!jvk) {
        vesjni_throw(env, LIBVES_E_PARAM, "veskey is null", NULL);
        return;
    }
    /* Elevate the session via the inherited primary (ves->vaultKey set by
     * the parent Vault that opened this child via Vault.subVault — typically
     * a Vault that just ran setVESkey-for-primary and still holds the
     * unlocked new primary as ves->vaultKey).
     *
     * libVES_refreshSession does GET /vaultKeys/{id}?fields=encSessionToken
     * against ves->vaultKey->id, decrypts with that key's privateKey, and
     * replaces ves->sessionToken with the short-lived elevated value the
     * server gates secondary-key mutations on. Mirrors libVES.js
     * setSecondaryKey -> elevateAuth. */
    if (!ves->vaultKey) {
        vesjni_throw(env, LIBVES_E_PARAM,
                     "setVESkey(secondary) needs an unlocked parent vault key — "
                     "open this Vault via parent.subVault() after the parent's setVESkey",
                     NULL);
        return;
    }
    /* Swap the persistent /me-level session for the short-lived per-key
     * one the server gates secondary-key mutations on. The vault key is
     * the parent's primary (REFUPped into this child by libVES_child via
     * subVault); the elevated token is written into this child's session
     * slot only. */
    if (!libVES_VaultKey_elevate(ves->vaultKey, ves)) {
        vesjni_throw_from(env, ves);
        return;
    }
    /* libVES_me lazy-fetches via /me when ves->me is unset — needs the session
     * token, which the unlocked-primary path already has. */
    libVES_User *me = libVES_me(ves);
    if (!me) {
        vesjni_throw_from(env, ves);
        return;
    }
    libVES_veskey *vk = vesjni_veskey_from_jba(env, jvk);
    if (!vk) return;
    libVES_VaultKey *new_vk = libVES_VaultKey_new(LIBVES_VK_SECONDARY, ves->keyAlgo, NULL, vk, ves);
    vesjni_wipe(vk->veskey, vk->keylen);
    libVES_veskey_free(vk);
    if (!new_vk) {
        vesjni_throw_from(env, ves);
        return;
    }
    /* REFUP balances the REFDN that VaultKey_free will run; ves->me and
     * ves->external stay owned by ves. */
    new_vk->user = libVES_REFUP(User, me);
    new_vk->external = libVES_REFUP(Ref, ves->external);
    if (!libVES_VaultKey_propagate(new_vk)) {
        libVES_VaultKey_free(new_vk);
        vesjni_throw_from(env, ves);
        return;
    }
    if (!libVES_VaultKey_post(new_vk)) {
        libVES_VaultKey_free(new_vk);
        vesjni_throw_from(env, ves);
        return;
    }
    /* libVES_VaultKey_post stashes new_vk into ves->unlockedKeys (weak ref via
     * libVES_VaultKey_ListCtlU — no freefn). Pull it back out before freeing
     * so a later libVES_lock doesn't walk a dangling pointer. */
    if (ves->unlockedKeys) libVES_List_remove(ves->unlockedKeys, new_vk);
    libVES_VaultKey_free(new_vk);
}

/* Create or rotate the user's PRIMARY vault key using a temp-password
 * (recovery_token) for HTTP basic auth. Mirrors ves-www/inc/passwd.html.php
 * vv_passwd_rekey(veskey, lost):
 *
 *   1. Generate a CURRENT-type vault key locked under veskey, no user, no
 *      external (server resolves "me" from basic auth).
 *   2. POST /me?fields=encSessionToken with body
 *        { vaultKeys: [ new_vk, optional { id: lostId, type: "lost" } ] }
 *      authenticated as Basic(email, passwd).
 *   3. Decrypt encSessionToken with the new key's private key and store on
 *      ves->sessionToken so subsequent calls (and Vault.sessionToken() readers)
 *      use the new bearer token.
 *
 * lostId == 0 → fresh primary, no existing key to demote (signup path).
 * lostId  > 0 → rotation: server demotes that vault key to type=lost on the
 *               same request.
 *
 * The email used for basic auth comes from ves->me->email, which the Vault
 * constructor populates from the ves:////email primary URI form (parsed via
 * libVES_User_fromPath in nativeNew). The new primary VaultKey itself has no
 * external — primary keys live unattached on the User.
 *
 * Side effect: ves->sessionToken is replaced on success — the existing token,
 * if any, is freed by libVES_setSessionToken. ves->vaultKey is left untouched
 * (the new key is discarded after decrypting the session token); the caller's
 * next operation will re-fetch via libVES_getVaultKey + libVES_unlock. */
JNIEXPORT void JNICALL
Java_com_vesvault_libves_Vault_nativeSetVESkeyPrimary(JNIEnv *env, jclass cls, jlong h,
                                                      jbyteArray jvk, jlong lostId, jstring jpasswd) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    if (!ves) {
        vesjni_throw(env, LIBVES_E_PARAM, "Vault is null", NULL);
        return;
    }
    if (!ves->me || !ves->me->email || !ves->me->email[0]) {
        vesjni_throw(env, LIBVES_E_PARAM,
                     "Primary setVESkey requires a Vault opened with a ves:////email URI",
                     NULL);
        return;
    }
    if (!jvk) {
        vesjni_throw(env, LIBVES_E_PARAM, "veskey is null", NULL);
        return;
    }
    if (!jpasswd) {
        vesjni_throw(env, LIBVES_E_PARAM, "Password is null", NULL);
        return;
    }
    libVES_veskey *vk = vesjni_veskey_from_jba(env, jvk);
    if (!vk) return;
    libVES_VaultKey *new_vk = libVES_VaultKey_new(LIBVES_VK_CURRENT, ves->keyAlgo, NULL, vk, ves);
    vesjni_wipe(vk->veskey, vk->keylen);
    libVES_veskey_free(vk);
    if (!new_vk) {
        vesjni_throw_from(env, ves);
        return;
    }
    /* Body: { vaultKeys: [ toJVar(new_vk), {id, type:"lost"}? ] }. With no
     * user and no external on new_vk, toJVar emits just type/algo/publicKey/
     * privateKey — matching the JS shape. */
    jVar *body = jVar_object();
    jVar *jvks = jVar_array();
    jVar_put(body, "vaultKeys", jvks);
    jVar_push(jvks, libVES_VaultKey_toJVar(new_vk));
    if (lostId > 0) {
        jVar *jlost = jVar_object();
        jVar_put(jlost, "id", jVar_int((long long) lostId));
        jVar_put(jlost, "type", jVar_string("lost"));
        jVar_push(jvks, jlost);
    }
    const char *passwd = (*env)->GetStringUTFChars(env, jpasswd, NULL);
    /* Also pull back vaultKeys(id) so we know the server-assigned id for the
     * new primary — needed for libVES_refreshSession (and any chained child
     * setVESkey) to address /vaultKeys/{id}. POST /me doesn't echo it by
     * default with just `encSessionToken` in fields. */
    jVar *rsp = libVES_REST_login(ves, "me?fields=encSessionToken,vaultKeys(id)", body,
                                  ves->me->email, passwd);
    (*env)->ReleaseStringUTFChars(env, jpasswd, passwd);
    jVar_free(body);
    if (!rsp) {
        libVES_VaultKey_free(new_vk);
        vesjni_throw_from(env, ves);
        return;
    }
    /* Pick the id of the freshly-created CURRENT key (the lost-rotation
     * entry, if any, is the SECOND in the array — order matches what we
     * pushed into the body). libVES_VaultKey_parseJVar doesn't touch id,
     * so set it manually. */
    jVar *vks_rsp = jVar_get(rsp, "vaultKeys");
    if (vks_rsp && jVar_isArray(vks_rsp) && jVar_count(vks_rsp) > 0) {
        jVar *id_jv = jVar_get(jVar_index(vks_rsp, 0), "id");
        if (id_jv) new_vk->id = (long long) jVar_getInt(id_jv);
    }
    const char *est = jVar_getStringP(jVar_get(rsp, "encSessionToken"));
    int ok = 0;
    if (est) {
        char *tk = NULL;
        int l = libVES_VaultKey_decrypt(new_vk, est, &tk);
        if (l > 0) {
            tk[l] = 0;
            libVES_setSessionToken(ves, tk);
            vesjni_wipe(tk, (size_t) l);
            ok = 1;
        }
        free(tk);
    }
    jVar_free(rsp);
    /* Keep new_vk as ves->vaultKey so a subsequent child Vault (opened via
     * Vault.subVault) inherits an UNLOCKED primary through libVES_child's
     * REFUP and can elevate via libVES_refreshSession before its own
     * setVESkey POST. Without this the child sees ves->vaultKey == NULL
     * and elevation can't run. */
    if (ok) {
        if (ves->vaultKey) libVES_REFDN(VaultKey, ves->vaultKey);
        ves->vaultKey = libVES_REFUP(VaultKey, new_vk);
        /* unlockedKeys is a weak-ref list (ListCtlU — no freefn); ves->vaultKey
         * carries the strong ref. */
        if (ves->unlockedKeys) libVES_List_push(ves->unlockedKeys, new_vk);
    }
    libVES_VaultKey_free(new_vk);
    if (!ok) {
        vesjni_throw(env, LIBVES_E_UNLOCK,
                     "Failed to decrypt session token from new primary key", NULL);
    }
}
