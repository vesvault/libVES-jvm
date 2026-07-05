/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
#ifndef LIBVES_JVM_JNI_UTIL_H
#define LIBVES_JVM_JNI_UTIL_H

#include <jni.h>
#include <stddef.h>
#include <openssl/crypto.h>

struct libVES;
struct jVar;

extern jclass    vesjni_cls_VESException;
extern jmethodID vesjni_ctor_VESException;

/* jVar marshaller globals — populated in JNI_OnLoad via vesjni_jvar_init. */
extern jclass    vesjni_cls_HashMap, vesjni_cls_ArrayList, vesjni_cls_Boolean,
                 vesjni_cls_Long, vesjni_cls_Double, vesjni_cls_Number,
                 vesjni_cls_CharSequence, vesjni_cls_Map, vesjni_cls_Iterable,
                 vesjni_cls_Map_Entry;
extern jmethodID vesjni_m_HashMap_init, vesjni_m_HashMap_put,
                 vesjni_m_ArrayList_init, vesjni_m_ArrayList_add,
                 vesjni_m_Boolean_valueOf, vesjni_m_Long_valueOf,
                 vesjni_m_Double_valueOf, vesjni_m_Boolean_booleanValue,
                 vesjni_m_Number_longValue, vesjni_m_Number_doubleValue,
                 vesjni_m_CharSequence_toString,
                 vesjni_m_Map_entrySet, vesjni_m_Iterable_iterator,
                 vesjni_m_Iterator_hasNext, vesjni_m_Iterator_next,
                 vesjni_m_Set_iterator,
                 vesjni_m_Map_Entry_getKey, vesjni_m_Map_Entry_getValue;

int vesjni_jvar_init(JNIEnv *env);

/* Convert a jVar tree to a Java Object tree (HashMap / ArrayList / Boolean /
 * Long / Double / String / null). May return NULL for jVar null. Caller owns
 * the resulting local ref. */
jobject vesjni_jvar_to_jobj(JNIEnv *env, struct jVar *jv);

/* Convert a Java Object tree to a jVar tree. Returns NULL only on a type
 * the marshaller does not recognise. Caller owns the resulting jVar. */
struct jVar *vesjni_jobj_to_jvar(JNIEnv *env, jobject obj);

/* Throw a VESException with explicit code and messages. */
void vesjni_throw(JNIEnv *env, int code, const char *message, const char *detail);

/* Pull the last error from a libVES * and throw VESException for it.
 * Resets the libVES error code as a side effect. */
void vesjni_throw_from(JNIEnv *env, struct libVES *ves);

/* Optimization-safe memory wipe for secret material. plain memset() before
 * free() is a documented dead-store-elimination trap; OPENSSL_cleanse is
 * the portable, volatile-tagged equivalent and libcrypto is already on the
 * link line via libVES. */
#define vesjni_wipe(buf, len) OPENSSL_cleanse((buf), (len))

#endif
