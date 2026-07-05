/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * jni_vesflow.c: native methods for com.vesvault.libves.VESFlow.
 * Wraps libVES_Flow (the high-level web auth orchestrator). nativeAuth
 * uses VESflow_recv directly so the externalId/VESkey can be handed
 * back to Java instead of unlocking the embedded libVES instance.
 *
 * The native handle is the libVES_Flow* directly; the underlying libVES*
 * lives at flow->ves, so no intermediate struct is needed. The libVES*
 * is borrowed from the Java-side Vault — the Vault retains ownership
 * (and is the one that frees it on close). VESFlow only manages the
 * libVES_Flow lifetime.
 ***************************************************************************/
#include "jni_util.h"
#include "jVar.h"
#include "libVES.h"
#include "libVES/Flow.h"
#include "VESflow.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_VESFlow_nativeStart(JNIEnv *env, jclass cls,
                                              jlong vaultHandle, jstring jlocal,
                                              jstring jparams) {
    (void) cls;
    libVES *ves = (libVES *) (intptr_t) vaultHandle;
    if (!ves || !jlocal) return 0;
    const char *local  = (*env)->GetStringUTFChars(env, jlocal, NULL);
    const char *params = jparams ? (*env)->GetStringUTFChars(env, jparams, NULL) : NULL;

    libVES_Flow *flow = libVES_Flow_new(ves, local);
    if (!flow || !libVES_Flow_start(flow, params)) {
        if (flow) libVES_Flow_free(flow);
        flow = NULL;
    }

    (*env)->ReleaseStringUTFChars(env, jlocal, local);
    if (params) (*env)->ReleaseStringUTFChars(env, jparams, params);
    return (jlong) (intptr_t) flow;
}

JNIEXPORT jstring JNICALL
Java_com_vesvault_libves_VESFlow_nativeUrl(JNIEnv *env, jclass cls, jlong h) {
    (void) cls;
    libVES_Flow *flow = (libVES_Flow *) (intptr_t) h;
    if (!flow) return NULL;
    const char *url = libVES_Flow_geturl(flow);
    return url ? (*env)->NewStringUTF(env, url) : NULL;
}

JNIEXPORT jint JNICALL
Java_com_vesvault_libves_VESFlow_nativeAuth(JNIEnv *env, jclass cls,
                                             jlong h, jstring jredirect, jobject out) {
    (void) cls;
    libVES_Flow *flow = (libVES_Flow *) (intptr_t) h;
    if (!flow || !jredirect || !out) return VESFLOW_E_ARG;

    const char *redirect = (*env)->GetStringUTFChars(env, jredirect, NULL);
    char *rwurl = NULL;
    struct jVar *jauth = NULL;
    int rs = VESflow_recv(flow->flow, redirect, &rwurl, &jauth, NULL);
    free(rwurl);
    (*env)->ReleaseStringUTFChars(env, jredirect, redirect);

    if (rs == VESFLOW_E_OK) {
        const char *extid = jVar_getStringP(jVar_get(jauth, "externalId"));
        const char *vk = jVar_getStringP(jVar_get(jauth, "VESkey"));
        if (extid && vk) {
            jclass out_cls = (*env)->GetObjectClass(env, out);
            jmethodID meth = (*env)->GetMethodID(env, out_cls, "setCreds",
                "(Ljava/lang/String;Ljava/lang/String;)V");
            if (meth) {
                jstring jext = (*env)->NewStringUTF(env, extid);
                jstring jvks = (*env)->NewStringUTF(env, vk);
                (*env)->CallVoidMethod(env, out, meth, jext, jvks);
                (*env)->DeleteLocalRef(env, jext);
                (*env)->DeleteLocalRef(env, jvks);
            } else {
                rs = VESFLOW_E_ARG;
            }
            (*env)->DeleteLocalRef(env, out_cls);
        } else {
            rs = VESFLOW_E_DATA;
        }
    }
    libVES_cleanseJVar(jauth);
    jVar_free(jauth);
    libVES_Flow_free(flow);
    return rs;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_VESFlow_nativeFree(JNIEnv *env, jclass cls, jlong h) {
    (void) env;
    (void) cls;
    libVES_Flow *flow = (libVES_Flow *) (intptr_t) h;
    if (flow) libVES_Flow_free(flow);
}
