/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 *
 * tls_root.c: optional CA-bundle support for the statically-linked libcurl,
 * exposed to consumers as Vault.Option.TLS_ROOT.
 *
 * Where the bundled libcurl has no system CA path it can find (e.g. Android),
 * the TLS handshake to the VES API fails ("Communication with the API server
 * failed"). This file is compiled INTO libVES.so (so it can call the
 * library-local curl_easy_setopt) and exposes two symbols the JNI shim uses:
 *   - vesjni_tlsroot_set(path)        stash a PEM bundle path
 *   - vesjni_tlsroot_httpinit(ves)    a libVES httpInitFn that applies CURLOPT_CAINFO
 *
 * The JNI installs vesjni_tlsroot_httpinit via LIBVES_O_HTTPINITFN; libVES calls
 * it before every REST request (libVES_REST_req), with ves->curl already created.
 * The path is a single process-global value (one CA bundle per process).
 ***************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "libVES.h"

static char *vesjni_tlsroot_path = NULL;

void vesjni_tlsroot_set(const char *path) {
    char *p = path ? strdup(path) : NULL;
    free(vesjni_tlsroot_path);
    vesjni_tlsroot_path = p;
}

void vesjni_tlsroot_httpinit(libVES *ves) {
    if (!ves || !vesjni_tlsroot_path) return;
    CURL *curl = (CURL *) libVES_getOption(ves, LIBVES_O_CURL);
    if (curl) curl_easy_setopt(curl, CURLOPT_CAINFO, vesjni_tlsroot_path);
}

/* Watch long-poll abort (see jni_watch.c). curl-touching, so it lives here with the
 * library-local libcurl. The watch child carries a heap stop-flag on its (otherwise unused)
 * libVES ->ref; this progress callback aborts the in-flight transfer the instant it is set,
 * so VESEventTarget.stop() breaks the long-poll within ~1s instead of waiting out the poll
 * window (the dying-watch-overlaps-re-login bug). */
static int vesjni_watch_progress(void *clientp, curl_off_t dt, curl_off_t dn, curl_off_t ut, curl_off_t un) {
    (void) dt; (void) dn; (void) ut; (void) un;
    const volatile int *stopflag = clientp;
    return (stopflag && *stopflag) ? 1 : 0;     /* non-zero -> CURLE_ABORTED_BY_CALLBACK */
}

/* httpInitFn for a watch child: apply the CA bundle AND (re)arm the abort callback. libVES
 * runs this before every REST request, after curl_easy_reset wipes options, so re-set each
 * time. The stop-flag is read from ves->ref (set by the JNI's vesjni_watch_arm). */
void vesjni_watch_httpinit(libVES *ves) {
    vesjni_tlsroot_httpinit(ves);
    if (!ves) return;
    CURL *curl = (CURL *) libVES_getOption(ves, LIBVES_O_CURL);
    if (!curl) return;
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, &vesjni_watch_progress);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, ves->ref);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
}
