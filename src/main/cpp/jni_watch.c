/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * jni_watch.c: real-time event watch — native methods for
 *   com.vesvault.libves.VESEventTarget (poll / setPoll / free) and the
 *   per-type watch factories on Vault / Item.
 *
 * The watch always runs on a CHILD libVES context (libVES_child) so the
 * long-poll does not monopolize the watched Vault's curl handle. The child is
 * created here and owned by the watch; nativeWatchFree releases both. The Java
 * worker thread drives one libVES_Watch_load per call (one long-poll cycle),
 * letting it observe its stop flag between polls — libVES_Watch_nextptr's own
 * internal poll loop would never return on an empty tail.
 ***************************************************************************/
#include "jni_util.h"
#include "jVar.h"
#include "libVES.h"
#include "libVES/List.h"
#include "libVES/Event.h"
#include "libVES/Watch.h"
#include "libVES/Ref.h"
#include "libVES/REST.h"
#include "libVES/Session.h"
#include "libVES/User.h"
#include "libVES/Util.h"
#include "libVES/VaultItem.h"
#include "libVES/VaultKey.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Defined in tls_root.c (compiled INTO libVES.so, where the library-local libcurl lives, so
   this module needs no curl headers): the watch child's httpInitFn — applies the CA bundle
   AND arms a curl progress callback that aborts the long-poll when the ->ref stop-flag set
   by vesjni_watch_arm / nativeWatchAbort is raised. */
extern void vesjni_watch_httpinit(libVES *ves);

#define VESJNI_EVENT_CLASS  "com/vesvault/libves/Event"
#define VESJNI_EVENT_CTOR_SIG \
    "(JIJLjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;)V"

#define VESJNI_DEFAULT_POLL_USEC  30000000LL   /* 30s */

/* Poll-timeout callback: the configured window is stashed in `arg`. */
static long long vesjni_watch_tmoutfn(libVES_Watch *w, void *arg) {
    (void) w;
    return (long long) (intptr_t) arg;
}

static void vesjni_watch_set_poll(libVES_Watch *w, long long usec) {
    libVES_Watch_setTimeoutFn(w, &vesjni_watch_tmoutfn, (void *) (intptr_t) usec);
}

/* ---- abortable long-poll ------------------------------------------------- *
 * The watch worker blocks inside one libVES_Watch_load (a long-poll held open up to the
 * poll window). With no abort, stop()/close() must wait that whole window out — and a
 * sign-out's dying watch then long-polls the API while the next sign-in races it on the
 * non-thread-safe native/TLS stack ("Communication with the API server failed" on
 * re-login). So: hang a heap stop-flag on the watch child's unused ->ref; the abort-aware
 * httpInitFn (vesjni_watch_httpinit, in tls_root.c with the library-local curl) installs a
 * progress callback that returns the flag to curl as CURLE_ABORTED_BY_CALLBACK. */

/* Arm <child> for abortable polling. Best-effort: without the flag the watch still works,
   it just isn't abortable (close falls back to waiting out the poll window). */
static void vesjni_watch_arm(libVES *child) {
    if (!child) return;
    int *flag = calloc(1, sizeof(int));
    if (!flag) return;
    child->ref = flag;                          /* read by nativeWatchAbort + the progress cb */
    child->httpInitFn = &vesjni_watch_httpinit;
}

/* Free a watch's child context (from libVES_child) while the PARENT is still
 * alive. Plain libVES_free is unsafe here: libVES_child REFUPs the parent's
 * external/vaultKey/me/propagators, but the parent commonly holds those at
 * refct 0 (e.g. the vault key stored by unlock is not REFUPed), so the child's
 * libVES_free would REFDN them to 0 and free them out from under the parent —
 * the parent's later libVES_free -> libVES_lock -> chkAttn -> libVES_me path
 * then reads freed memory (verified use-after-free under valgrind).
 *
 * Instead undo libVES_child's REFUPs with a raw decrement (no free-at-0) so the
 * parent retains ownership at its original count, then release only the child's
 * OWN resources. The child owns no unlocked keys of its own (its unlockedKeys
 * list holds weak refs to the parent's keys, ListCtlU), so libVES_lock is
 * unnecessary and skipped — which also avoids the chkAttn network call on
 * teardown. Mirror of libVES_child: keep in sync if it REFUPs/allocates
 * different fields. */
static void vesjni_free_child(libVES *child) {
    if (!child) return;
    if (child->external)    child->external->refct--;
    if (child->vaultKey)    child->vaultKey->refct--;
    if (child->me)          child->me->refct--;
    if (child->propagators) child->propagators->refct--;
    child->external = NULL;
    child->vaultKey = NULL;
    child->me = NULL;
    child->propagators = NULL;
    libVES_REST_done(child);                   /* child's own curl handle */
    free(child->ref);                          /* the abortable-poll stop-flag (vesjni_watch_arm) */
    free(child->sessionToken);                 /* child strdup'd its own copy */
    free(child->errorBuf);
    libVES_REFDN(List, child->unlockedKeys);   /* child's own (weak-ref) list */
    free(child);
}

/* Marshal one libVES_Event into a Java Event. evCls/ctor are resolved once per
 * batch by the caller. Returns a local ref (or NULL on a JNI failure). */
static jobject vesjni_marshal_event(JNIEnv *env, jclass evCls, jmethodID ctor,
                                    libVES_Event *ev) {
    char *itemUri = NULL;
    jint itemType = -1;
    if (ev->vitem) {
        itemUri = libVES_VaultItem_toURI(ev->vitem);
        if (!itemUri) itemUri = libVES_VaultItem_toURIi(ev->vitem);
        itemType = (jint) libVES_VaultItem_getType(ev->vitem);
    }
    char *vkUri = NULL;
    if (ev->vkey) {
        vkUri = libVES_VaultKey_toURI(ev->vkey);
        if (!vkUri) vkUri = libVES_VaultKey_toURIi(ev->vkey);
    }
    const char *userEmail = libVES_User_getEmail(ev->user);
    const char *creatorEmail = libVES_User_getEmail(ev->creator);
    jlong sesId = 0;
    const char *remote = NULL, *ua = NULL;
    if (ev->session) {
        sesId = (jlong) libVES_Session_getId(ev->session);
        remote = libVES_Session_getRemote(ev->session);
        ua = libVES_Session_getUserAgent(ev->session);
    }

    jstring jItemUri = itemUri ? (*env)->NewStringUTF(env, itemUri) : NULL;
    jstring jVkUri   = vkUri ? (*env)->NewStringUTF(env, vkUri) : NULL;
    jstring jUser    = userEmail ? (*env)->NewStringUTF(env, userEmail) : NULL;
    jstring jCreator = creatorEmail ? (*env)->NewStringUTF(env, creatorEmail) : NULL;
    jstring jRemote  = remote ? (*env)->NewStringUTF(env, remote) : NULL;
    jstring jUA      = ua ? (*env)->NewStringUTF(env, ua) : NULL;
    free(itemUri);
    free(vkUri);

    jobject obj = (*env)->NewObject(env, evCls, ctor,
        (jlong) ev->id, (jint) ev->type, (jlong) ev->recordedAt,
        jItemUri, itemType, jVkUri, jUser, jCreator,
        sesId, jRemote, jUA);

    /* A large batch would otherwise blow the local-ref table. */
    if (jItemUri) (*env)->DeleteLocalRef(env, jItemUri);
    if (jVkUri)   (*env)->DeleteLocalRef(env, jVkUri);
    if (jUser)    (*env)->DeleteLocalRef(env, jUser);
    if (jCreator) (*env)->DeleteLocalRef(env, jCreator);
    if (jRemote)  (*env)->DeleteLocalRef(env, jRemote);
    if (jUA)      (*env)->DeleteLocalRef(env, jUA);
    return obj;
}

JNIEXPORT jobjectArray JNICALL
Java_com_vesvault_libves_VESEventTarget_nativeWatchPoll(JNIEnv *env, jclass cls,
                                                        jlong wh, jlong start,
                                                        jint count, jint flags) {
    (void) cls;
    libVES_Watch *w = (libVES_Watch *) (intptr_t) wh;
    if (!w) {
        vesjni_throw(env, LIBVES_E_PARAM, "Watch handle is null", NULL);
        return NULL;
    }
    jclass evCls = (*env)->FindClass(env, VESJNI_EVENT_CLASS);
    if (!evCls) return NULL;
    jmethodID ctor = (*env)->GetMethodID(env, evCls, "<init>", VESJNI_EVENT_CTOR_SIG);
    if (!ctor) return NULL;

    libVES_List *list = libVES_Watch_load(w, (long long) start, (int) count, (int) flags);
    if (!list) {
        /* Distinguish a real error from an empty reverse/poll result: load
         * returns NULL on REST failure (error code set) and also on an empty
         * reverse window (no error). getErrorInfo resets the code either way. */
        const char *str = NULL, *msg = NULL;
        int code = libVES_getErrorInfo(w->ves, &str, &msg);
        if (code != LIBVES_E_OK) {
            vesjni_throw(env, code, str, msg);
            return NULL;
        }
        return (*env)->NewObjectArray(env, 0, evCls, NULL);
    }

    jsize n = (jsize) list->len;
    jobjectArray arr = (*env)->NewObjectArray(env, n, evCls, NULL);
    if (!arr) return NULL;
    for (jsize i = 0; i < n; i++) {
        libVES_Event *ev = (libVES_Event *) list->list[i];
        if (!ev) continue;
        jobject jev = vesjni_marshal_event(env, evCls, ctor, ev);
        if (!jev) return NULL;   /* pending JNI exception */
        (*env)->SetObjectArrayElement(env, arr, i, jev);
        (*env)->DeleteLocalRef(env, jev);
    }
    return arr;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_VESEventTarget_nativeWatchSetPoll(JNIEnv *env, jclass cls,
                                                           jlong wh, jlong usec) {
    (void) env; (void) cls;
    libVES_Watch *w = (libVES_Watch *) (intptr_t) wh;
    if (w) vesjni_watch_set_poll(w, (long long) usec);
}

/* Signal the in-flight long-poll to abort (set the child's stop-flag); the progress
   callback returns it within ~1s as CURLE_ABORTED_BY_CALLBACK. The caller (stop()) holds
   the VESEventTarget monitor and has confirmed the handle is live, mutually excluded with
   nativeWatchFree, so w + w->ves->ref are valid here. */
JNIEXPORT void JNICALL
Java_com_vesvault_libves_VESEventTarget_nativeWatchAbort(JNIEnv *env, jclass cls, jlong wh) {
    (void) env; (void) cls;
    libVES_Watch *w = (libVES_Watch *) (intptr_t) wh;
    if (!w || !w->ves) return;
    int *flag = (int *) w->ves->ref;
    if (flag) *flag = 1;
}

JNIEXPORT void JNICALL
Java_com_vesvault_libves_VESEventTarget_nativeWatchFree(JNIEnv *env, jclass cls, jlong wh) {
    (void) env; (void) cls;
    libVES_Watch *w = (libVES_Watch *) (intptr_t) wh;
    if (!w) return;
    /* The watch was built on a child context we own. Free the watch (which
     * frees its event list, releasing the refs those events hold on child
     * structures) before tearing down the child itself. vesjni_free_child, not
     * libVES_free — see the note there for why the child can't be freed
     * normally while the parent is alive. */
    libVES *child = w->ves;
    libVES_Watch_free(w);
    vesjni_free_child(child);
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Vault_nativeWatchVault(JNIEnv *env, jclass cls,
                                                jlong h, jlong vkh) {
    (void) cls;
    libVES *parent = (libVES *) (intptr_t) h;
    if (!parent) {
        vesjni_throw(env, LIBVES_E_PARAM, "Vault is null", NULL);
        return 0;
    }
    libVES *child = libVES_child(parent);
    if (!child) {
        vesjni_throw(env, LIBVES_E_INTERNAL, "libVES_child failed", NULL);
        return 0;
    }
    /* libVES_Watch_VaultKey_events keys off libVES_getVaultKey(child). The
     * child inherits the parent's vault key via libVES_child's REFUP; for the
     * explicit-handle (sub-vault) case where the slot is empty, plug it in. */
    libVES_VaultKey *vk = libVES_getVaultKey(child);
    if (!vk && vkh) {
        child->vaultKey = libVES_REFUP(VaultKey, (libVES_VaultKey *) (intptr_t) vkh);
        vk = child->vaultKey;
    }
    libVES_Watch *w = vk ? libVES_Watch_VaultKey_events(child)
                         : libVES_Watch_User_events(child);
    if (!w) {
        vesjni_throw_from(env, child);
        libVES_free(child);
        return 0;
    }
    vesjni_watch_set_poll(w, VESJNI_DEFAULT_POLL_USEC);
    vesjni_watch_arm(child);
    return (jlong) (intptr_t) w;
}

JNIEXPORT jlong JNICALL
Java_com_vesvault_libves_Item_nativeWatchItem(JNIEnv *env, jclass cls,
                                              jlong h, jlong vih, jstring juri) {
    (void) cls;
    libVES *parent = (libVES *) (intptr_t) h;
    if (!parent) {
        vesjni_throw(env, LIBVES_E_PARAM, "Vault is null", NULL);
        return 0;
    }
    libVES *child = libVES_child(parent);
    if (!child) {
        vesjni_throw(env, LIBVES_E_INTERNAL, "libVES_child failed", NULL);
        return 0;
    }
    /* Resolve the vault item. A native-backed Item hands its vitem pointer
     * directly (we only read its id); a URI-backed Item loads a throwaway vitem
     * on the child just to learn the id. libVES_Watch_VaultItem_events copies
     * the id into the watch URI and retains nothing. */
    libVES_VaultItem *vi = (libVES_VaultItem *) (intptr_t) vih;
    libVES_VaultItem *tmp = NULL;
    if (!vi) {
        if (!juri) {
            libVES_free(child);
            vesjni_throw(env, LIBVES_E_PARAM, "Item needs a native handle or a URI to watch", NULL);
            return 0;
        }
        const char *uri_orig = (*env)->GetStringUTFChars(env, juri, NULL);
        const char *uri = uri_orig;
        tmp = libVES_VaultItem_loadFromURI(&uri, child);
        (*env)->ReleaseStringUTFChars(env, juri, uri_orig);
        if (!tmp) {
            vesjni_throw_from(env, child);
            libVES_free(child);
            return 0;
        }
        vi = tmp;
    }
    libVES_Watch *w = libVES_Watch_VaultItem_events(child, vi);
    if (tmp) libVES_VaultItem_free(tmp);
    if (!w) {
        vesjni_throw_from(env, child);
        libVES_free(child);
        return 0;
    }
    vesjni_watch_set_poll(w, VESJNI_DEFAULT_POLL_USEC);
    vesjni_watch_arm(child);
    return (jlong) (intptr_t) w;
}
