/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * jni_itemcipher.c: native methods for com.vesvault.libves.ItemCipher and
 * com.vesvault.libves.Item.nativeCipher.
 *
 * libVES_VaultItem_getCipher always returns a fresh, caller-owned cipher
 * initialized with the existing key bytes; the VaultItem itself does NOT
 * retain a pointer. setCipher only stores the serialized key + algo on the
 * vitem. So ItemCipher's nativeHandle is independent of any VaultItem
 * lifecycle.
 ***************************************************************************/
#include "jni_util.h"
#include "jVar.h"
#include "libVES.h"
#include "libVES/Cipher.h"
#include "libVES/List.h"
#include "libVES/VaultItem.h"
#include "libVES/VaultKey.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Shared with jni_item.c */
libVES_List *build_share_list(JNIEnv *env, libVES *ves, jobjectArray jshares, int *ok);

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Item_nativeCipher(JNIEnv *env, jclass cls,
                                            jlong h, jstring juri,
                                            jstring jalgo, jobjectArray jshares) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) h;
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES_VaultItem *vitem = libVES_VaultItem_fromURI(&uri, ves);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vitem) {
        vesjni_throw_from(env, ves);
        return 0;
    }

    /* If the item has a value, try reading the existing cipher. */
    libVES_Cipher *ci = NULL;
    if (libVES_VaultItem_getValue(vitem)) {
        ci = libVES_VaultItem_getCipher(vitem, ves);
        if (!ci) (void) libVES_getError(ves);  /* swallow "no cipher yet" */
    }

    if (!ci) {
        const struct libVES_CiAlgo *algo = NULL;
        if (jalgo) {
            const char *algo_str = (*env)->GetStringUTFChars(env, jalgo, NULL);
            algo = libVES_Cipher_algoFromStr(algo_str);
            (*env)->ReleaseStringUTFChars(env, jalgo, algo_str);
        } else {
            algo = ves->cipherAlgo;
        }
        if (!algo) {
            libVES_VaultItem_free(vitem);
            vesjni_throw(env, LIBVES_E_UNSUPPORTED, "Unknown cipher algorithm", NULL);
            return 0;
        }

        ci = libVES_Cipher_new(algo, ves, 0, NULL);
        if (!ci) {
            libVES_VaultItem_free(vitem);
            vesjni_throw_from(env, ves);
            return 0;
        }
        if (!libVES_VaultItem_setCipher(vitem, ci)) {
            libVES_Cipher_free(ci);
            libVES_VaultItem_free(vitem);
            vesjni_throw_from(env, ves);
            return 0;
        }

        int ok = 1;
        if (jshares) {
            libVES_List *share = build_share_list(env, ves, jshares, &ok);
            if (ok) {
                struct jVar *new_entries = libVES_VaultItem_entries(
                    vitem, share, LIBVES_SH_ADD | LIBVES_SH_UPD);
                if (new_entries) vitem->entries = new_entries;
                else ok = 0;
            }
            libVES_List_free(share);
        }
        if (ok) ok = libVES_VaultItem_post(vitem, ves);
        if (!ok) {
            libVES_Cipher_free(ci);
            libVES_VaultItem_free(vitem);
            vesjni_throw_from(env, ves);
            return 0;
        }
    }

    libVES_VaultItem_free(vitem);
    return (jlong) (intptr_t) ci;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vesvault_libves_ItemCipher_nativeEncrypt(JNIEnv *env, jclass cls,
                                                   jlong h, jbyteArray jdata,
                                                   jboolean jfinal) {
    (void) cls;
    libVES_Cipher *ci = (libVES_Cipher *) (intptr_t) h;
    jsize len = (*env)->GetArrayLength(env, jdata);
    char *pt = malloc((size_t) len);
    if (!pt) {
        vesjni_throw(env, LIBVES_E_INTERNAL, "Out of memory", NULL);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, jdata, 0, len, (jbyte *) pt);

    char *ct = NULL;
    int outlen = libVES_Cipher_encrypt(ci, jfinal == JNI_TRUE, pt, (size_t) len, &ct);
    vesjni_wipe(pt, (size_t) len);
    free(pt);

    if (outlen < 0) {
        free(ct);
        vesjni_throw(env, LIBVES_E_CRYPTO, "Encryption failed", NULL);
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize) outlen);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, (jsize) outlen, (const jbyte *) ct);
    free(ct);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vesvault_libves_ItemCipher_nativeDecrypt(JNIEnv *env, jclass cls,
                                                   jlong h, jbyteArray jdata,
                                                   jboolean jfinal) {
    (void) cls;
    libVES_Cipher *ci = (libVES_Cipher *) (intptr_t) h;
    jsize len = (*env)->GetArrayLength(env, jdata);
    char *ct = malloc((size_t) len);
    if (!ct) {
        vesjni_throw(env, LIBVES_E_INTERNAL, "Out of memory", NULL);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, jdata, 0, len, (jbyte *) ct);

    char *pt = NULL;
    int outlen = libVES_Cipher_decrypt(ci, jfinal == JNI_TRUE, ct, (size_t) len, &pt);
    free(ct);

    if (outlen < 0) {
        if (pt) { vesjni_wipe(pt, (size_t) outlen); free(pt); }
        vesjni_throw(env, LIBVES_E_CRYPTO, "Decryption failed", NULL);
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize) outlen);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, (jsize) outlen, (const jbyte *) pt);
    vesjni_wipe(pt, (size_t) outlen);
    free(pt);
    return result;
}

JNIEXPORT jobject JNICALL
Java_com_vesvault_libves_ItemCipher_nativeGetMeta(JNIEnv *env, jclass cls, jlong h) {
    (void) cls;
    libVES_Cipher *ci = (libVES_Cipher *) (intptr_t) h;
    struct jVar *jv = libVES_Cipher_getMeta(ci);
    return vesjni_jvar_to_jobj(env, jv);
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_ItemCipher_nativeSetMeta(JNIEnv *env, jclass cls,
                                                    jlong vesH, jstring juri,
                                                    jlong ciH, jobject jmeta) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) vesH;
    libVES_Cipher *ci = (libVES_Cipher *) (intptr_t) ciH;

    struct jVar *jv = vesjni_jobj_to_jvar(env, jmeta);
    if (!jv) {
        vesjni_throw(env, LIBVES_E_PARAM, "Unsupported meta value type", NULL);
        return;
    }
    if (!libVES_Cipher_setMeta(ci, jv)) {
        jVar_free(jv);
        vesjni_throw_from(env, ves);
        return;
    }
    /* setMeta took ownership of jv */

    /* Persist by re-serializing the cipher onto the item and posting. */
    const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
    const char *uri = uri_orig;
    libVES_VaultItem *vitem = libVES_VaultItem_fromURI(&uri, ves);
    (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
    if (!vitem) {
        vesjni_throw_from(env, ves);
        return;
    }
    int ok = libVES_VaultItem_setCipher(vitem, ci)
          && libVES_VaultItem_post(vitem, ves);
    libVES_VaultItem_free(vitem);
    if (!ok) vesjni_throw_from(env, ves);
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_ItemCipher_nativeFree(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    libVES_Cipher *ci = (libVES_Cipher *) (intptr_t) h;
    libVES_Cipher_free(ci);
}
