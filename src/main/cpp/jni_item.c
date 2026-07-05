/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * jni_item.c: native methods for com.vesvault.libves.Item.
 *
 * v1 vertical slice: get / put route through libVES_getValue / libVES_putValue.
 * The Item handle is the URI string carried on the Java side; no native
 * libVES_VaultItem * yet. share/add/remove/cipher land in v2 once Item
 * starts carrying a real VaultItem handle.
 ***************************************************************************/
#include "jni_util.h"
#include "jVar.h"
#include "libVES.h"
#include "libVES/List.h"
#include "libVES/Ref.h"
#include "libVES/Util.h"
#include "libVES/VaultItem.h"
#include "libVES/VaultKey.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Build a libVES_List of VaultKey pointers from a Java String[] of share URIs.
 * Defined further down (and also used by jni_itemcipher.c); forward-declared
 * here so the put/cipher paths above the definition can call it. */
libVES_List *build_share_list(JNIEnv *env, libVES *ves, jobjectArray jshares, int *ok);

/* Read both Item.nativeHandle (libVES_VaultItem *) and parent.nativeHandle
 * (libVES *) off the Java object. Used by instance-method natives that work
 * directly on the vitem pointer. Field IDs are looked up per call — these
 * paths aren't hot enough to warrant caching. */
static int vesjni_item_get_handles(JNIEnv *env, jobject self,
                                    libVES **ves, libVES_VaultItem **vi,
                                    jfieldID *out_handleFid) {
    jclass cls = (*env)->GetObjectClass(env, self);
    jfieldID parentFid = (*env)->GetFieldID(env, cls, "parent", "Lcom/vesvault/libves/Vault;");
    jfieldID handleFid = (*env)->GetFieldID(env, cls, "nativeHandle", "J");
    if (!parentFid || !handleFid) return 0;
    jobject parentObj = (*env)->GetObjectField(env, self, parentFid);
    if (!parentObj) return 0;
    jclass parentCls = (*env)->GetObjectClass(env, parentObj);
    jfieldID parentHandleFid = (*env)->GetFieldID(env, parentCls, "nativeHandle", "J");
    if (!parentHandleFid) return 0;
    *ves = (libVES *) (intptr_t) (*env)->GetLongField(env, parentObj, parentHandleFid);
    *vi  = (libVES_VaultItem *) (intptr_t) (*env)->GetLongField(env, self, handleFid);
    if (out_handleFid) *out_handleFid = handleFid;
    return 1;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vesvault_libves_Item_nativeGetVitem(JNIEnv *env, jobject self) {
    libVES *ves = NULL;
    libVES_VaultItem *vi = NULL;
    jfieldID handleFid = NULL;
    if (!vesjni_item_get_handles(env, self, &ves, &vi, &handleFid)) {
        vesjni_throw(env, LIBVES_E_INTERNAL, "Item field lookup failed", NULL);
        return NULL;
    }
    if (!vi) {
        vesjni_throw(env, LIBVES_E_PARAM, "Vault item is null", NULL);
        return NULL;
    }
    /* Fetch+decrypt by internal id if the value isn't already on the vitem.
     * Mirrors the swap pattern in libVES_VaultKey_getVESkey: REFDN the old
     * pointer, REFUP the freshly loaded one, write it back to Java so the
     * cache survives this call. */
    if (!vi->value) {
        if (!vi->id) {
            vesjni_throw(env, LIBVES_E_PARAM, "Vault item id is not set", NULL);
            return NULL;
        }
        libVES_Ref *ref = libVES_Ref_new(vi->id);
        libVES_VaultItem *loaded = ref ? libVES_VaultItem_get(ref, ves) : NULL;
        libVES_Ref_free(ref);
        if (!loaded || !loaded->value) {
            libVES_VaultItem_free(loaded);
            vesjni_throw_from(env, ves);
            return NULL;
        }
        libVES_REFDN(VaultItem, vi);
        vi = libVES_REFUP(VaultItem, loaded);
        (*env)->SetLongField(env, self, handleFid, (jlong) (intptr_t) vi);
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize) vi->len);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, (jsize) vi->len, (const jbyte *) vi->value);
    return result;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Item_nativeFreeVitem(JNIEnv *env, jclass cls, jlong h) {
    (void) env; (void) cls;
    libVES_VaultItem *vi = (libVES_VaultItem *) (intptr_t) h;
    if (vi) libVES_VaultItem_free(vi);
}

JNIEXPORT jbyteArray JNICALL
Java_com_vesvault_libves_Item_nativeGet(JNIEnv *env, jclass cls, jlong h, jstring juri) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri = (*env)->GetStringUTFChars(env, juri, NULL);
    size_t len = 0;
    char *val = libVES_getValue(ves, uri, &len, NULL);
    (*env)->ReleaseStringUTFChars(env, juri, uri);
    if (!val) {
        vesjni_throw_from(env, ves);
        return NULL;
    }
    jbyteArray out = (*env)->NewByteArray(env, (jsize) len);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, (jsize) len, (const jbyte *) val);
    free(val);
    return out;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Item_nativePut(JNIEnv *env, jclass cls,
                                         jlong h, jstring juri,
                                         jbyteArray jval, jobjectArray jshares) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri = (*env)->GetStringUTFChars(env, juri, NULL);
    jsize vlen = (*env)->GetArrayLength(env, jval);

    char *val = malloc((size_t) vlen);
    if (!val) {
        (*env)->ReleaseStringUTFChars(env, juri, uri);
        vesjni_throw(env, LIBVES_E_INTERNAL, "Out of memory", NULL);
        return;
    }
    (*env)->GetByteArrayRegion(env, jval, 0, vlen, (jbyte *) val);

    size_t nshares = 0;
    const char **shares = NULL;
    jstring *jstrs = NULL;
    if (jshares) {
        nshares = (size_t) (*env)->GetArrayLength(env, jshares);
        shares = calloc(nshares, sizeof(*shares));
        jstrs  = calloc(nshares, sizeof(*jstrs));
        if (!shares || !jstrs) {
            free(shares); free(jstrs);
            vesjni_wipe(val, (size_t) vlen);
            free(val);
            (*env)->ReleaseStringUTFChars(env, juri, uri);
            vesjni_throw(env, LIBVES_E_INTERNAL, "Out of memory", NULL);
            return;
        }
        for (size_t i = 0; i < nshares; i++) {
            jstrs[i]  = (jstring) (*env)->GetObjectArrayElement(env, jshares, (jsize) i);
            shares[i] = (*env)->GetStringUTFChars(env, jstrs[i], NULL);
        }
    }

    int ok = libVES_putValue(ves, uri, (size_t) vlen, val, nshares, shares);

    vesjni_wipe(val, (size_t) vlen);
    free(val);
    if (shares) {
        for (size_t i = 0; i < nshares; i++) {
            (*env)->ReleaseStringUTFChars(env, jstrs[i], shares[i]);
            (*env)->DeleteLocalRef(env, jstrs[i]);
        }
        free(shares);
        free(jstrs);
    }
    (*env)->ReleaseStringUTFChars(env, juri, uri);

    if (!ok) vesjni_throw_from(env, ves);
}

/* Create/replace an item with a raw value of an explicit type (LIBVES_VI_*) plus
 * optional cipher metadata (e.g. {"a":"VE"}), shared to jshares. Unlike nativePut
 * (libVES_putValue, which writes a STRING item with no meta), this drives the
 * VaultItem primitives so the caller controls the value type and meta — e.g. a
 * FILE item with meta.a set is the form libVES_VaultItem_getCipher reads back.
 * The value buffer is wiped after the post (it may be key material). */
JNIEXPORT void JNICALL
Java_com_vesvault_libves_Item_nativePutRaw(JNIEnv *env, jclass cls,
                                           jlong h, jstring juri,
                                           jbyteArray jval, jint jtype, jobject jmeta,
                                           jobjectArray jshares) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES_VaultItem *vitem = libVES_VaultItem_fromURI(&uri, ves);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vitem) {
        vesjni_throw_from(env, ves);
        return;
    }

    /* Value -> item value of the requested type; setValue0 owns the buffer. */
    jsize vlen = (*env)->GetArrayLength(env, jval);
    char *val = malloc((size_t) vlen);
    if (!val) {
        libVES_VaultItem_free(vitem);
        vesjni_throw(env, LIBVES_E_INTERNAL, "Out of memory", NULL);
        return;
    }
    (*env)->GetByteArrayRegion(env, jval, 0, vlen, (jbyte *) val);
    libVES_VaultItem_setValue0(vitem, (size_t) vlen, val, (int) jtype);

    /* Optional metadata (e.g. {"a":"VE"}); setMeta takes ownership of the jVar. */
    int ok = 1;
    struct jVar *meta = NULL;
    if (jmeta) {
        meta = vesjni_jobj_to_jvar(env, jmeta);
        if (meta) libVES_VaultItem_setMeta(vitem, meta);
        else ok = 0;
    }

    /* Shares -> vaultEntries: encrypt the value for each recipient + the owner. */
    if (ok && jshares) {
        libVES_List *share = build_share_list(env, ves, jshares, &ok);
        if (ok) {
            struct jVar *new_entries = libVES_VaultItem_entries(vitem, share, LIBVES_SH_ADD | LIBVES_SH_UPD);
            if (new_entries) vitem->entries = new_entries;
            else ok = 0;
        }
        libVES_List_free(share);
    }

    if (ok) ok = libVES_VaultItem_post(vitem, ves);

    if (vitem->value) vesjni_wipe(vitem->value, vitem->len);
    libVES_VaultItem_free(vitem);
    if (!ok) {
        if (jmeta && !meta) vesjni_throw(env, LIBVES_E_PARAM, "Unsupported meta value type", NULL);
        else vesjni_throw_from(env, ves);
    }
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Item_nativeVersion(JNIEnv *env, jclass cls, jlong h, jstring juri) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES_VaultItem *vitem = libVES_VaultItem_loadFromURI(&uri, ves);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vitem) {
        vesjni_throw_from(env, ves);
        return 0;
    }
    long long id = libVES_VaultItem_getId(vitem);
    libVES_VaultItem_free(vitem);
    return (jlong) id;
}

JNIEXPORT jint JNICALL
Java_com_vesvault_libves_Item_nativeType(JNIEnv *env, jclass cls, jlong h, jstring juri) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES_VaultItem *vitem = libVES_VaultItem_loadFromURI(&uri, ves);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vitem) {
        vesjni_throw_from(env, ves);
        return -1;
    }
    int t = libVES_VaultItem_getType(vitem);
    libVES_VaultItem_free(vitem);
    return (jint) t;
}

JNIEXPORT jboolean JNICALL
Java_com_vesvault_libves_Item_nativeExists(JNIEnv *env, jclass cls, jlong h, jstring juri) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri = (*env)->GetStringUTFChars(env, juri, NULL);
    int r = libVES_fileExists(ves, uri);
    (*env)->ReleaseStringUTFChars(env, juri, uri);
    if (r < 0) {
        vesjni_throw_from(env, ves);
        return JNI_FALSE;
    }
    return r ? JNI_TRUE : JNI_FALSE;
}

/* Build a libVES_List of VaultKey pointers from a Java String[] of URIs.
 * Returns the list (always allocated, may be empty on error). *ok set to 0 on
 * any URI parse failure. Shared with jni_itemcipher.c. */
libVES_List *build_share_list(JNIEnv *env, libVES *ves,
                               jobjectArray jshares, int *ok) {
    libVES_List *share = libVES_List_new(&libVES_VaultKey_ListCtl);
    *ok = 1;
    if (!jshares) return share;
    jsize n = (*env)->GetArrayLength(env, jshares);
    for (jsize i = 0; i < n; i++) {
        jstring jstr = (jstring) (*env)->GetObjectArrayElement(env, jshares, i);
        const char *s_orig = (*env)->GetStringUTFChars(env, jstr, NULL);
        const char *s = s_orig;
        libVES_VaultKey *vk = libVES_VaultKey_fromURI(&s, ves);
        (*env)->ReleaseStringUTFChars(env, jstr, s_orig);
        (*env)->DeleteLocalRef(env, jstr);
        if (!vk || !libVES_List_push(share, vk)) { *ok = 0; break; }
    }
    return share;
}

JNIEXPORT jobjectArray JNICALL
Java_com_vesvault_libves_Item_nativeShare(JNIEnv *env, jclass cls,
                                           jlong h, jstring juri) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES_VaultItem *vitem = libVES_VaultItem_loadFromURI(&uri, ves);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vitem) {
        vesjni_throw_from(env, ves);
        return NULL;
    }

    jsize count = 0;
    libVES_VaultKey **p = NULL;
    while ((p = libVES_VaultItem_nextShare(vitem, p))) count++;

    jclass str_cls = (*env)->FindClass(env, "java/lang/String");
    jobjectArray result = (*env)->NewObjectArray(env, count, str_cls, NULL);
    if (!result) {
        libVES_VaultItem_free(vitem);
        return NULL;
    }

    jsize i = 0;
    p = NULL;
    while ((p = libVES_VaultItem_nextShare(vitem, p))) {
        char *vk_uri = libVES_VaultKey_toURI(*p);
        if (vk_uri) {
            jstring js = (*env)->NewStringUTF(env, vk_uri);
            (*env)->SetObjectArrayElement(env, result, i, js);
            (*env)->DeleteLocalRef(env, js);
            free(vk_uri);
        }
        i++;
    }
    libVES_VaultItem_free(vitem);
    return result;
}

static void item_modify_shares(JNIEnv *env, libVES *ves,
                                jstring juri, jobjectArray jshares, int flags) {
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES_VaultItem *vitem = libVES_VaultItem_loadFromURI(&uri, ves);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vitem) {
        vesjni_throw_from(env, ves);
        return;
    }
    /* For ADD we need vitem->value populated so libVES_VaultItem_entries can
     * re-encrypt it for any newly added share keys. loadFromURI fetches
     * metadata but doesn't decrypt; getValue triggers the decrypt. DEL
     * doesn't touch the value, so skip the round trip there. */
    int ok = 1;
    if (flags & LIBVES_SH_ADD) {
        if (!libVES_VaultItem_getValue(vitem)) ok = 0;
    }
    libVES_List *share = ok ? build_share_list(env, ves, jshares, &ok) : NULL;
    if (ok) {
        /* libVES_VaultItem_entries detaches vitem->entries into its return
         * value, mutates it, and returns it; the caller is responsible for
         * putting it back so post() can serialize a non-empty request. */
        struct jVar *new_entries = libVES_VaultItem_entries(vitem, share, flags);
        if (new_entries) vitem->entries = new_entries;
        else ok = 0;
    }
    if (ok) ok = libVES_VaultItem_post(vitem, ves);
    if (share) libVES_List_free(share);
    libVES_VaultItem_free(vitem);
    if (!ok) vesjni_throw_from(env, ves);
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Item_nativeAdd(JNIEnv *env, jclass cls,
                                         jlong h, jstring juri,
                                         jobjectArray jshares) {
    (void) cls;
    /* ADD|UPD: ADD encrypts the value for each new share key, UPD also
     * re-encrypts for existing keys so post() ships a non-empty vaultEntries
     * array. Without UPD, entries() produces no work for unchanged shares
     * and post() sends a request with no entries -> server rejects. */
    item_modify_shares(env, (libVES *) (intptr_t) h, juri, jshares,
                       LIBVES_SH_ADD | LIBVES_SH_UPD);
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Item_nativeRemove(JNIEnv *env, jclass cls,
                                            jlong h, jstring juri,
                                            jobjectArray jshares) {
    (void) cls;
    item_modify_shares(env, (libVES *) (intptr_t) h, juri, jshares, LIBVES_SH_DEL);
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_Item_nativeDelete(JNIEnv *env, jclass cls, jlong h, jstring juri) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    /* libVES_deleteFile is declared in libVES.h but unimplemented — go via
     * the VaultItem primitives instead. */
    libVES_VaultItem *vitem = libVES_VaultItem_loadFromURI(&uri, ves);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vitem) {
        vesjni_throw_from(env, ves);
        return;
    }
    int ok = libVES_VaultItem_delete(vitem, ves);
    libVES_VaultItem_free(vitem);
    if (!ok) vesjni_throw_from(env, ves);
}
