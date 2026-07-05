/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * AutoCloseable wrapper around {@code struct VESlocker} (libVES.c).
 * VESlocker is the PIN-protected key-storage service for saved-veskey flows.
 *
 * <p>Each entry tracks a server-side failed-attempt counter. A successful
 * {@link #decrypt} does NOT reset that counter — to rotate, the caller must
 * follow the read with a fresh {@link #encrypt} call (which mints a new
 * entryid + seed and starts the counter back at zero) and persist the new
 * entry string in place of the old one.
 *
 * <p>On failure inspect {@link #lastError()}, {@link #lastHttpCode()}, and
 * {@link #retryAfter()} to distinguish a bad PIN / throttled state (httpCode
 * == 403, error == E_RETRY, retryAfter seconds) from transport / crypto
 * failures.
 */
public final class VESLocker implements AutoCloseable {
    long nativeHandle;

    public static final int E_OK     = 0;
    public static final int E_LIB    = -1;
    public static final int E_BUF    = -2;
    public static final int E_API    = -3;
    public static final int E_CRYPTO = -4;
    public static final int E_RETRY  = -40;

    /** Create a VESlocker pointing at {@code apiUrl}, e.g.
     *  {@code "https://www.vesvault.com/api/VESlocker"}. */
    public VESLocker(@NotNull String apiUrl) {
        nativeHandle = nativeNew(apiUrl);
    }

    /**
     * Install a native {@code void (*)(VESlocker *)} hook as the
     * {@code httpInitFn} on the underlying handle. The hook fires once
     * per libcurl handle (on first request) — the place to wire TLS
     * trust / SSL_CTX setup. VESlocker doesn't share libcurl with any
     * libVES, so {@link Vault#initFn} on a Vault doesn't reach this
     * handle; the caller is expected to install the same TLS setup
     * here via a matching native function pointer.
     */
    public @NotNull VESLocker initFn(long fnPtr) {
        if (nativeHandle != 0 && fnPtr != 0) nativeInitFn(nativeHandle, fnPtr);
        return this;
    }

    /** Encrypt {@code value} under {@code pin}; returns the encoded entry
     *  string {@code "apiUrl#entryid.seed.ctext"} or null on failure. */
    public @Nullable String encrypt(@NotNull String value, @NotNull String pin) {
        return nativeHandle == 0 ? null : nativeEncrypt(nativeHandle, value, pin);
    }

    /** Decrypt {@code vlentry} under {@code pin}; returns plaintext or null. */
    public @Nullable String decrypt(@NotNull String vlentry, @NotNull String pin) {
        return nativeHandle == 0 ? null : nativeDecrypt(nativeHandle, vlentry, pin);
    }

    /** One of {@link #E_OK}, {@link #E_LIB}, {@link #E_BUF}, {@link #E_API},
     *  {@link #E_CRYPTO}, {@link #E_RETRY}. */
    public int lastError() {
        return nativeHandle == 0 ? E_BUF : nativeLastError(nativeHandle);
    }

    /** HTTP status of the most recent getkey roundtrip. 403 pairs with
     *  {@link #E_RETRY}. */
    public int lastHttpCode() {
        return nativeHandle == 0 ? 0 : nativeLastHttpCode(nativeHandle);
    }

    /** Seconds to wait before retry (from the server's Refresh header); 0 if
     *  unknown. */
    public int retryAfter() {
        return nativeHandle == 0 ? 0 : nativeRetryAfter(nativeHandle);
    }

    @Override
    public void close() {
        long h = nativeHandle;
        nativeHandle = 0;
        if (h != 0) nativeFree(h);
    }

    private static native long nativeNew(@NotNull String apiUrl);
    private static native void nativeInitFn(long handle, long fnPtr);
    private static native void nativeFree(long handle);
    private static native @Nullable String nativeEncrypt(long handle, @NotNull String value, @NotNull String pin);
    private static native @Nullable String nativeDecrypt(long handle, @NotNull String vlentry, @NotNull String pin);
    private static native int  nativeLastError(long handle);
    private static native int  nativeLastHttpCode(long handle);
    private static native int  nativeRetryAfter(long handle);

    static {
        System.loadLibrary("VESjni");
    }
}
