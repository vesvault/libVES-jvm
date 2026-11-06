/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
/*
 * OfflineKey: a vault key held as PEM, used with no Vault and no network.
 *
 * It decrypts an item encrypted to its public key -- what `ves -Y KEY -i DATA`
 * makes, and what `ves -y KEY -I DATA` reads back. The context's API and poll
 * URLs point nowhere (the ves CLI's offline mode does the same), so nothing a
 * key does here can reach the VES API, even by a lazy fetch.
 *
 * It is for an app that has to unwrap a cipher key while the VES API is
 * unreachable, with a copy of the vault's private key that it keeps itself.
 *
 * The PEM is copied and kept for the key's lifetime, then wiped: autoPEM only
 * reads it, but nothing here relies on that. Plaintext buffers are wiped
 * before they are freed.
 */
#include "jni_util.h"
#include "libVES.h"
#include "libVES/VaultKey.h"
#include "libVES/KeyAlgo_EVP.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define VESJNI_OFFLINE_URL "offline://no-network/"

typedef struct {
    libVES *ves;
    libVES_VaultKey *vkey;
    char *pem;
} vesjni_offline;

static void vesjni_offline_free(vesjni_offline *o) {
    if (!o) return;
    if (o->vkey) libVES_VaultKey_free(o->vkey);
    if (o->ves) libVES_free(o->ves);
    if (o->pem) {
        OPENSSL_cleanse(o->pem, strlen(o->pem));
        free(o->pem);
    }
    free(o);
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_OfflineKey_nativeFromPEM(JNIEnv *env, jclass cls, jstring jpem, jbyteArray jveskey) {
    (void) cls;
    vesjni_offline *o = calloc(1, sizeof(*o));
    if (!o) { vesjni_throw(env, LIBVES_E_INTERNAL, "out of memory", NULL); return 0; }
    const char *pem = (*env)->GetStringUTFChars(env, jpem, NULL);
    if (!pem) { free(o); return 0; }
    o->pem = strdup(pem);
    (*env)->ReleaseStringUTFChars(env, jpem, pem);
    if (!o->pem) { free(o); vesjni_throw(env, LIBVES_E_INTERNAL, "out of memory", NULL); return 0; }

    if (!(o->ves = libVES_new(NULL))) {
        vesjni_offline_free(o);
        vesjni_throw(env, LIBVES_E_INTERNAL, "libVES_new failed", NULL);
        return 0;
    }
    libVES_setOption(o->ves, LIBVES_O_APIURL, VESJNI_OFFLINE_URL);
    libVES_setOption(o->ves, LIBVES_O_POLLURL, VESJNI_OFFLINE_URL);

    libVES_veskey *vk = NULL;
    if (jveskey) {
        jsize l = (*env)->GetArrayLength(env, jveskey);
        jbyte *b = (*env)->GetByteArrayElements(env, jveskey, NULL);
        if (b) {
            vk = libVES_veskey_new((size_t) l, (const char *) b);
            OPENSSL_cleanse(b, (size_t) l);
            (*env)->ReleaseByteArrayElements(env, jveskey, b, JNI_ABORT);
        }
    }
    /* autoPEM: EVP (RSA, EC) first, then OQS (ML-KEM), as `ves -yf` without -G. */
    o->vkey = libVES_VaultKey_new(LIBVES_VK_CURRENT, &libVES_KeyAlgo_autoPEM, o->pem, vk, o->ves);
    if (vk) libVES_veskey_free(vk);
    if (!o->vkey) {
        vesjni_throw_from(env, o->ves);
        vesjni_offline_free(o);
        return 0;
    }
    return (jlong) (intptr_t) o;
}

JNIEXPORT jbyteArray JNICALL
Java_com_vesvault_libves_OfflineKey_nativeDecrypt(JNIEnv *env, jclass cls, jlong h, jstring jct) {
    (void) cls;
    vesjni_offline *o = (vesjni_offline *) (intptr_t) h;
    if (!o || !o->vkey) { vesjni_throw(env, LIBVES_E_PARAM, "the key is closed", NULL); return NULL; }
    const char *ct = (*env)->GetStringUTFChars(env, jct, NULL);
    if (!ct) return NULL;
    char *pt = NULL;
    int l = libVES_VaultKey_decrypt(o->vkey, ct, &pt);
    (*env)->ReleaseStringUTFChars(env, jct, ct);
    if (l < 0 || !pt) {
        vesjni_throw_from(env, o->ves);
        return NULL;
    }
    jbyteArray out = (*env)->NewByteArray(env, l);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, l, (const jbyte *) pt);
    OPENSSL_cleanse(pt, (size_t) l);
    free(pt);
    return out;
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_OfflineKey_nativePublicKeyPEM(JNIEnv *env, jclass cls, jlong h) {
    (void) cls;
    vesjni_offline *o = (vesjni_offline *) (intptr_t) h;
    if (!o || !o->vkey) { vesjni_throw(env, LIBVES_E_PARAM, "the key is closed", NULL); return NULL; }
    const char *pub = libVES_VaultKey_getPublicKey(o->vkey);
    return pub ? (*env)->NewStringUTF(env, pub) : NULL;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_OfflineKey_nativeFree(JNIEnv *env, jclass cls, jlong h) {
    (void) env; (void) cls;
    vesjni_offline_free((vesjni_offline *) (intptr_t) h);
}
