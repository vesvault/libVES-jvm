/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * AutoCloseable wrapper around {@code libVES_Flow}. Usage:
 *
 * <pre>
 *   try (Vault vault = new Vault("ves://vesmail.email/" + emailHint)) {
 *       // any vault setup (initFn, …) goes here, before start()
 *       try (VESFlow flow = VESFlow.start(vault, localUrl, null)) {
 *           String url = flow.url();
 *           // launch a browser at `url`; wait for the deep-link callback
 *           VESFlow.Creds creds = new VESFlow.Creds();
 *           int rs = flow.auth(redirectUrl, creds);
 *           if (rs == OK) { ... creds.externalId, creds.veskey ... }
 *       }
 *   }
 * </pre>
 *
 * <p>The flow borrows the Vault's native libVES — the Vault must outlive
 * the VESFlow. A successful {@link #auth} consumes (and frees) the native
 * flow handle; a failed {@link #auth} does not — call {@link #close} either
 * way to be safe.
 */
public final class VESFlow implements AutoCloseable {
    long nativeHandle;

    public static final int OK     = 0;
    public static final int E_XCHG = -1;
    public static final int E_ARG  = -2;
    public static final int E_KEY  = -3;
    public static final int E_DATA = -4;
    public static final int E_ENC  = -5;
    public static final int E_MSG  = -6;

    private VESFlow(long h) { this.nativeHandle = h; }

    /**
     * Start a flow. The flow borrows {@code vault}'s underlying native
     * {@code libVES *}; the caller retains ownership of {@code vault} and
     * is responsible for closing it (the Vault must outlive the VESFlow).
     * The Vault must carry a domain (and typically an externalId hint) in
     * its URI, e.g. {@code "ves://vesmail.email/user@example.com"}, and
     * should not be unlocked yet.
     *
     * @param vault    pre-configured Vault (domain + hint in URI; optional
     *                 {@link Vault#initFn} / {@link Vault#sessionToken} done)
     * @param localUrl app-served redirect URL; VES appends the auth hash
     *                 fragment for {@link #auth} to consume
     * @param params   optional extra query string (starts with {@code "?"}),
     *                 or null for defaults
     * @return a started VESFlow, or null on failure
     */
    public static @Nullable VESFlow start(@NotNull Vault vault,
                                          @NotNull String localUrl,
                                          @Nullable String params) {
        if (vault.nativeHandle == 0) return null;
        long h = nativeStart(vault.nativeHandle, localUrl, params);
        return h == 0 ? null : new VESFlow(h);
    }

    /** The VES authorization URL to open in a browser. */
    public @Nullable String url() {
        return nativeHandle == 0 ? null : nativeUrl(nativeHandle);
    }

    /**
     * Hand the deep-link callback URL back to libVES. On success, fills
     * {@code out} via its {@code setCreds(externalId, veskey)} method.
     * Either way the native handle is consumed; {@link #close} afterwards
     * is a no-op.
     */
    public int auth(@NotNull String redirectUrl, @NotNull Creds out) {
        if (nativeHandle == 0) return E_ARG;
        int rs = nativeAuth(nativeHandle, redirectUrl, out);
        nativeHandle = 0;
        return rs;
    }

    @Override
    public void close() {
        long h = nativeHandle;
        nativeHandle = 0;
        if (h != 0) nativeFree(h);
    }

    /** Receiver for the native-side {@code setCreds(externalId, veskey)} callback. */
    public static class Creds {
        public @Nullable String externalId;
        public @Nullable String veskey;

        /** Called from JNI on successful auth. */
        public void setCreds(@NotNull String externalId, @NotNull String veskey) {
            this.externalId = externalId;
            this.veskey = veskey;
        }
    }

    private static native long    nativeStart(long vaultHandle, @NotNull String localUrl, @Nullable String params);
    private static native @Nullable String nativeUrl(long handle);
    private static native int     nativeAuth(long handle, @NotNull String redirectUrl, @NotNull Object out);
    private static native void    nativeFree(long handle);

    static {
        System.loadLibrary("VESjni");
    }
}
