/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
#include "jni_util.h"
#include "libVES.h"
#include <string.h>

jclass    vesjni_cls_VESException  = NULL;
jmethodID vesjni_ctor_VESException = NULL;

void vesjni_throw(JNIEnv *env, int code, const char *message, const char *detail) {
    if ((*env)->ExceptionCheck(env)) return;
    if (!vesjni_cls_VESException || !vesjni_ctor_VESException) {
        jclass re = (*env)->FindClass(env, "java/lang/RuntimeException");
        if (re) (*env)->ThrowNew(env, re, "libves-jvm: VESException not cached");
        return;
    }
    jstring jmsg = message ? (*env)->NewStringUTF(env, message) : NULL;
    jstring jdet = detail  ? (*env)->NewStringUTF(env, detail)  : NULL;
    jobject ex = (*env)->NewObject(env, vesjni_cls_VESException, vesjni_ctor_VESException,
                                   (jint) code, jmsg, jdet);
    if (ex) (*env)->Throw(env, (jthrowable) ex);
}

void vesjni_throw_from(JNIEnv *env, struct libVES *ves) {
    const char *str = NULL;
    const char *msg = NULL;
    int code = libVES_getErrorInfo(ves, &str, &msg);
    vesjni_throw(env, code, str, msg);
}
