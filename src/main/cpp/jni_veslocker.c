/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * jni_veslocker.c: native methods for com.vesvault.libves.VESLocker.
 ***************************************************************************/
#include "jni_util.h"
#include "libVES.h"
#include "VESlocker.h"
#include <openssl/crypto.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_VESLocker_nativeNew(JNIEnv *env, jclass cls, jstring jurl) {
    (void) cls;
    if (!jurl) return 0;
    const char *url = (*env)->GetStringUTFChars(env, jurl, NULL);
    VESlocker *vl = VESlocker_new(NULL);
    if (vl) {
        /* VESlocker_new keeps the URL pointer as-is; take ownership via a
         * strdup so the URL stays valid after we release the jstring. */
        char *copy = strdup(url);
        free(vl->allocurl);
        vl->allocurl = copy;
        vl->apiUrl = copy;
    }
    (*env)->ReleaseStringUTFChars(env, jurl, url);
    return (jlong) (intptr_t) vl;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_VESLocker_nativeInitFn(JNIEnv *env, jclass cls, jlong h, jlong fnPtr) {
    (void) env; (void) cls;
    VESlocker *vl = (VESlocker *) (intptr_t) h;
    if (vl) vl->httpInitFn = (void (*)(VESlocker *)) (intptr_t) fnPtr;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_VESLocker_nativeFree(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    VESlocker *vl = (VESlocker *) (intptr_t) h;
    VESlocker_free(vl);
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_VESLocker_nativeEncrypt(JNIEnv *env, jclass cls,
                                                  jlong h, jstring jvalue, jstring jpin) {
    (void) cls;
    VESlocker *vl = (VESlocker *) (intptr_t) h;
    if (!vl) return NULL;
    const char *value = (*env)->GetStringUTFChars(env, jvalue, NULL);
    jsize vlen = (*env)->GetStringUTFLength(env, jvalue);
    const char *pin = (*env)->GetStringUTFChars(env, jpin, NULL);
    char *entry = VESlocker_encrypt(vl, value, (size_t) vlen, pin, NULL);
    jstring rs = NULL;
    if (entry) {
        rs = (*env)->NewStringUTF(env, entry);
        free(entry);
    }
    (*env)->ReleaseStringUTFChars(env, jvalue, value);
    (*env)->ReleaseStringUTFChars(env, jpin, pin);
    return rs;
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_VESLocker_nativeDecrypt(JNIEnv *env, jclass cls,
                                                  jlong h, jstring jentry, jstring jpin) {
    (void) cls;
    VESlocker *vl = (VESlocker *) (intptr_t) h;
    if (!vl) return NULL;
    const char *entry = (*env)->GetStringUTFChars(env, jentry, NULL);
    const char *pin = (*env)->GetStringUTFChars(env, jpin, NULL);
    jstring rs = NULL;
    VESlocker_entry *e = VESlocker_entry_parse(entry);
    if (e) {
        /* Web stores entries with a relative URL ("/api/VESlocker") because
         * the page XHRs same-origin. We want the absolute URL we set on the
         * VESlocker handle; clearing e->url makes decrypt skip its seturl. */
        if (e->url && e->url[0] == '/') e->url = NULL;
        size_t bufsz = VESlocker_decsize(e);
        char *val = NULL;
        int len = VESlocker_decrypt(vl, e, pin, &val);
        if (val) {
            if (len > 0) {
                char *zterm = malloc((size_t) len + 1);
                if (zterm) {
                    memcpy(zterm, val, (size_t) len);
                    zterm[len] = 0;
                    rs = (*env)->NewStringUTF(env, zterm);
                    OPENSSL_cleanse(zterm, (size_t) len);
                    free(zterm);
                }
            }
            OPENSSL_cleanse(val, bufsz);
            free(val);
        }
        VESlocker_entry_free(e);
    }
    (*env)->ReleaseStringUTFChars(env, jentry, entry);
    (*env)->ReleaseStringUTFChars(env, jpin, pin);
    return rs;
}

JNIEXPORT jint JNICALL
Java_com_vesvault_libves_VESLocker_nativeLastError(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    VESlocker *vl = (VESlocker *) (intptr_t) h;
    return vl ? vl->error : VESLOCKER_E_BUF;
}

JNIEXPORT jint JNICALL
Java_com_vesvault_libves_VESLocker_nativeLastHttpCode(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    VESlocker *vl = (VESlocker *) (intptr_t) h;
    return vl ? (jint) vl->httpcode : 0;
}

JNIEXPORT jint JNICALL
Java_com_vesvault_libves_VESLocker_nativeRetryAfter(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    VESlocker *vl = (VESlocker *) (intptr_t) h;
    return vl ? (jint) vl->retry : 0;
}
