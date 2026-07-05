/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * jni_jvar.c: bi-directional marshaller between jVar trees and Java tree
 * objects (HashMap / ArrayList / Boolean / Long / Double / String / null).
 *
 * Used by ItemCipher.meta() at the moment; will pick up any other jVar-shaped
 * surface (item meta, future event payloads, etc.) once we expose them.
 ***************************************************************************/
#include "jni_util.h"
#include "jVar.h"
#include <stdlib.h>
#include <string.h>

jclass    vesjni_cls_HashMap = NULL,
          vesjni_cls_ArrayList = NULL,
          vesjni_cls_Boolean = NULL,
          vesjni_cls_Long = NULL,
          vesjni_cls_Double = NULL,
          vesjni_cls_Number = NULL,
          vesjni_cls_CharSequence = NULL,
          vesjni_cls_Map = NULL,
          vesjni_cls_Iterable = NULL,
          vesjni_cls_Map_Entry = NULL;

jmethodID vesjni_m_HashMap_init = NULL,
          vesjni_m_HashMap_put = NULL,
          vesjni_m_ArrayList_init = NULL,
          vesjni_m_ArrayList_add = NULL,
          vesjni_m_Boolean_valueOf = NULL,
          vesjni_m_Long_valueOf = NULL,
          vesjni_m_Double_valueOf = NULL,
          vesjni_m_Boolean_booleanValue = NULL,
          vesjni_m_Number_longValue = NULL,
          vesjni_m_Number_doubleValue = NULL,
          vesjni_m_CharSequence_toString = NULL,
          vesjni_m_Map_entrySet = NULL,
          vesjni_m_Iterable_iterator = NULL,
          vesjni_m_Iterator_hasNext = NULL,
          vesjni_m_Iterator_next = NULL,
          vesjni_m_Set_iterator = NULL,
          vesjni_m_Map_Entry_getKey = NULL,
          vesjni_m_Map_Entry_getValue = NULL;

static jclass cache_class(JNIEnv *env, const char *name) {
    jclass local = (*env)->FindClass(env, name);
    if (!local) return NULL;
    jclass global = (jclass) (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    return global;
}

int vesjni_jvar_init(JNIEnv *env) {
#define CACHE_CLS(target, name) \
    if (!(target = cache_class(env, name))) return 0;
#define CACHE_M(target, cls, name, sig) \
    if (!(target = (*env)->GetMethodID(env, cls, name, sig))) return 0;
#define CACHE_SM(target, cls, name, sig) \
    if (!(target = (*env)->GetStaticMethodID(env, cls, name, sig))) return 0;

    CACHE_CLS(vesjni_cls_HashMap,      "java/util/HashMap");
    CACHE_CLS(vesjni_cls_ArrayList,    "java/util/ArrayList");
    CACHE_CLS(vesjni_cls_Boolean,      "java/lang/Boolean");
    CACHE_CLS(vesjni_cls_Long,         "java/lang/Long");
    CACHE_CLS(vesjni_cls_Double,       "java/lang/Double");
    CACHE_CLS(vesjni_cls_Number,       "java/lang/Number");
    CACHE_CLS(vesjni_cls_CharSequence, "java/lang/CharSequence");
    CACHE_CLS(vesjni_cls_Map,          "java/util/Map");
    CACHE_CLS(vesjni_cls_Iterable,     "java/lang/Iterable");
    CACHE_CLS(vesjni_cls_Map_Entry,    "java/util/Map$Entry");

    CACHE_M(vesjni_m_HashMap_init,   vesjni_cls_HashMap,   "<init>", "()V");
    CACHE_M(vesjni_m_HashMap_put,    vesjni_cls_HashMap,   "put",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    CACHE_M(vesjni_m_ArrayList_init, vesjni_cls_ArrayList, "<init>", "()V");
    CACHE_M(vesjni_m_ArrayList_add,  vesjni_cls_ArrayList, "add",
            "(Ljava/lang/Object;)Z");

    CACHE_SM(vesjni_m_Boolean_valueOf, vesjni_cls_Boolean, "valueOf",
             "(Z)Ljava/lang/Boolean;");
    CACHE_SM(vesjni_m_Long_valueOf,    vesjni_cls_Long,    "valueOf",
             "(J)Ljava/lang/Long;");
    CACHE_SM(vesjni_m_Double_valueOf,  vesjni_cls_Double,  "valueOf",
             "(D)Ljava/lang/Double;");

    CACHE_M(vesjni_m_Boolean_booleanValue,   vesjni_cls_Boolean,
            "booleanValue", "()Z");
    CACHE_M(vesjni_m_Number_longValue,       vesjni_cls_Number,
            "longValue",   "()J");
    CACHE_M(vesjni_m_Number_doubleValue,     vesjni_cls_Number,
            "doubleValue", "()D");
    CACHE_M(vesjni_m_CharSequence_toString,  vesjni_cls_CharSequence,
            "toString",    "()Ljava/lang/String;");

    CACHE_M(vesjni_m_Map_entrySet, vesjni_cls_Map,
            "entrySet",    "()Ljava/util/Set;");
    CACHE_M(vesjni_m_Iterable_iterator, vesjni_cls_Iterable,
            "iterator",    "()Ljava/util/Iterator;");

    jclass cls_Set = (*env)->FindClass(env, "java/util/Set");
    if (!cls_Set) return 0;
    CACHE_M(vesjni_m_Set_iterator, cls_Set, "iterator",
            "()Ljava/util/Iterator;");
    (*env)->DeleteLocalRef(env, cls_Set);

    jclass cls_It = (*env)->FindClass(env, "java/util/Iterator");
    if (!cls_It) return 0;
    CACHE_M(vesjni_m_Iterator_hasNext, cls_It, "hasNext", "()Z");
    CACHE_M(vesjni_m_Iterator_next,    cls_It, "next",    "()Ljava/lang/Object;");
    (*env)->DeleteLocalRef(env, cls_It);

    CACHE_M(vesjni_m_Map_Entry_getKey,   vesjni_cls_Map_Entry,
            "getKey",   "()Ljava/lang/Object;");
    CACHE_M(vesjni_m_Map_Entry_getValue, vesjni_cls_Map_Entry,
            "getValue", "()Ljava/lang/Object;");

#undef CACHE_CLS
#undef CACHE_M
#undef CACHE_SM
    return 1;
}

jobject vesjni_jvar_to_jobj(JNIEnv *env, jVar *jv) {
    if (!jv || jVar_isNull(jv)) return NULL;
    if (jVar_isBool(jv)) {
        return (*env)->CallStaticObjectMethod(env, vesjni_cls_Boolean,
            vesjni_m_Boolean_valueOf,
            jVar_getBool(jv) ? JNI_TRUE : JNI_FALSE);
    }
    if (jVar_isInt(jv)) {
        return (*env)->CallStaticObjectMethod(env, vesjni_cls_Long,
            vesjni_m_Long_valueOf, (jlong) jVar_getInt(jv));
    }
    if (jVar_isFloat(jv)) {
        return (*env)->CallStaticObjectMethod(env, vesjni_cls_Double,
            vesjni_m_Double_valueOf, (jdouble) jVar_getFloat(jv));
    }
    if (jVar_isString(jv)) {
        size_t len = jv->len;
        char *buf = malloc(len + 1);
        if (!buf) return NULL;
        memcpy(buf, jv->vString, len);
        buf[len] = 0;
        jstring s = (*env)->NewStringUTF(env, buf);
        free(buf);
        return s;
    }
    if (jVar_isArray(jv)) {
        jobject list = (*env)->NewObject(env, vesjni_cls_ArrayList,
            vesjni_m_ArrayList_init);
        if (!list) return NULL;
        for (size_t i = 0; i < jv->len; i++) {
            jobject elem = vesjni_jvar_to_jobj(env, jv->vArray[i]);
            (*env)->CallBooleanMethod(env, list, vesjni_m_ArrayList_add, elem);
            if (elem) (*env)->DeleteLocalRef(env, elem);
        }
        return list;
    }
    if (jVar_isObject(jv)) {
        jobject map = (*env)->NewObject(env, vesjni_cls_HashMap,
            vesjni_m_HashMap_init);
        if (!map) return NULL;
        for (size_t i = 0; i < jv->len; i++) {
            jVar *kv_key = jv->vObject[i].key;
            jVar *kv_val = jv->vObject[i].val;
            jobject jkey = vesjni_jvar_to_jobj(env, kv_key);
            jobject jval = vesjni_jvar_to_jobj(env, kv_val);
            jobject prev = (*env)->CallObjectMethod(env, map,
                vesjni_m_HashMap_put, jkey, jval);
            if (prev) (*env)->DeleteLocalRef(env, prev);
            if (jkey) (*env)->DeleteLocalRef(env, jkey);
            if (jval) (*env)->DeleteLocalRef(env, jval);
        }
        return map;
    }
    return NULL;
}

jVar *vesjni_jobj_to_jvar(JNIEnv *env, jobject obj) {
    if (!obj) return jVar_null();

    if ((*env)->IsInstanceOf(env, obj, vesjni_cls_Boolean)) {
        jboolean v = (*env)->CallBooleanMethod(env, obj,
            vesjni_m_Boolean_booleanValue);
        return jVar_bool(v == JNI_TRUE);
    }
    if ((*env)->IsInstanceOf(env, obj, vesjni_cls_Number)) {
        /* Long, Integer, Short, Byte → integer; Float, Double → float.
         * Use Double class as the float discriminator. */
        if ((*env)->IsInstanceOf(env, obj, vesjni_cls_Double)) {
            jdouble d = (*env)->CallDoubleMethod(env, obj,
                vesjni_m_Number_doubleValue);
            return jVar_float((jVar_TFloat) d);
        }
        jlong l = (*env)->CallLongMethod(env, obj, vesjni_m_Number_longValue);
        return jVar_int((jVar_TInt) l);
    }
    if ((*env)->IsInstanceOf(env, obj, vesjni_cls_CharSequence)) {
        jstring js = (jstring) (*env)->CallObjectMethod(env, obj,
            vesjni_m_CharSequence_toString);
        const char *s = (*env)->GetStringUTFChars(env, js, NULL);
        jsize n = (*env)->GetStringUTFLength(env, js);
        jVar *out = jVar_stringl(s, (size_t) n);
        (*env)->ReleaseStringUTFChars(env, js, s);
        (*env)->DeleteLocalRef(env, js);
        return out;
    }
    if ((*env)->IsInstanceOf(env, obj, vesjni_cls_Map)) {
        jVar *map = jVar_object();
        jobject set = (*env)->CallObjectMethod(env, obj, vesjni_m_Map_entrySet);
        jobject it = (*env)->CallObjectMethod(env, set, vesjni_m_Set_iterator);
        while ((*env)->CallBooleanMethod(env, it, vesjni_m_Iterator_hasNext)) {
            jobject entry = (*env)->CallObjectMethod(env, it, vesjni_m_Iterator_next);
            jobject jkey = (*env)->CallObjectMethod(env, entry, vesjni_m_Map_Entry_getKey);
            jobject jval = (*env)->CallObjectMethod(env, entry, vesjni_m_Map_Entry_getValue);
            /* Map keys must be CharSequence — non-string keys are out of
             * scope for v1 (cipher meta is always string-keyed in practice). */
            if (!(*env)->IsInstanceOf(env, jkey, vesjni_cls_CharSequence)) {
                (*env)->DeleteLocalRef(env, jkey);
                if (jval) (*env)->DeleteLocalRef(env, jval);
                (*env)->DeleteLocalRef(env, entry);
                continue;
            }
            jstring sk = (jstring) (*env)->CallObjectMethod(env, jkey,
                vesjni_m_CharSequence_toString);
            const char *ck = (*env)->GetStringUTFChars(env, sk, NULL);
            jVar *vv = vesjni_jobj_to_jvar(env, jval);
            jVar_put(map, ck, vv);
            (*env)->ReleaseStringUTFChars(env, sk, ck);
            (*env)->DeleteLocalRef(env, sk);
            (*env)->DeleteLocalRef(env, jkey);
            if (jval) (*env)->DeleteLocalRef(env, jval);
            (*env)->DeleteLocalRef(env, entry);
        }
        (*env)->DeleteLocalRef(env, it);
        (*env)->DeleteLocalRef(env, set);
        return map;
    }
    if ((*env)->IsInstanceOf(env, obj, vesjni_cls_Iterable)) {
        jVar *arr = jVar_array();
        jobject it = (*env)->CallObjectMethod(env, obj, vesjni_m_Iterable_iterator);
        while ((*env)->CallBooleanMethod(env, it, vesjni_m_Iterator_hasNext)) {
            jobject elem = (*env)->CallObjectMethod(env, it, vesjni_m_Iterator_next);
            jVar *ve = vesjni_jobj_to_jvar(env, elem);
            jVar_push(arr, ve);
            if (elem) (*env)->DeleteLocalRef(env, elem);
        }
        (*env)->DeleteLocalRef(env, it);
        return arr;
    }
    return NULL;
}
