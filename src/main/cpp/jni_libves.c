/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * jni_libves.c: JNI_OnLoad — caches global refs used by the throw helper.
 ***************************************************************************/
#include "jni_util.h"
#include <jni.h>

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass cls = (*env)->FindClass(env, "com/vesvault/libves/VESException");
    if (!cls) return JNI_ERR;
    vesjni_cls_VESException = (jclass) (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);

    vesjni_ctor_VESException = (*env)->GetMethodID(
        env, vesjni_cls_VESException, "<init>",
        "(ILjava/lang/String;Ljava/lang/String;)V");
    if (!vesjni_ctor_VESException) return JNI_ERR;

    if (!vesjni_jvar_init(env)) return JNI_ERR;

    return JNI_VERSION_1_6;
}
