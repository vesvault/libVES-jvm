/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Map;

/**
 * Stream cipher attached to an {@link Item}. Wraps a native
 * {@code libVES_Cipher *}.
 *
 * <p>Obtained via {@link Item#cipher()}. {@code encrypt}/{@code decrypt} are
 * stateful — pass {@code finalChunk=true} on the last call of a stream.
 *
 * <p>The native cipher is independent of any {@code libVES_VaultItem *};
 * closing the parent {@link Item} or {@link Vault} does not free this object.
 * Always close the ItemCipher (or use try-with-resources).
 */
public final class ItemCipher implements AutoCloseable {
    long nativeHandle;
    @SuppressWarnings("unused") Item parent;

    ItemCipher() {}

    @SuppressWarnings("unchecked")
    public @Nullable Map<String, Object> meta() {
        Object o = nativeGetMeta(nativeHandle);
        if (o == null) return null;
        if (o instanceof Map) return (Map<String, Object>) o;
        throw new IllegalStateException("Cipher meta is not an object: " + o.getClass());
    }

    /**
     * Replace the cipher metadata and persist by re-serializing the cipher
     * onto its parent {@link Item} and posting it. Requires the parent Item
     * to be writable.
     */
    public void meta(@NotNull Map<String, Object> meta) throws VESException {
        // Re-serializes + posts onto the owning Vault's context; take its lock.
        // (encrypt/decrypt below stay lock-free: they touch only this cipher's
        // own stream state, which is single-thread by contract anyway.)
        synchronized (parent.parent.ctxLock) {
            nativeSetMeta(parent.parent.nativeHandle, parent.uri, nativeHandle, meta);
        }
    }

    public @NotNull byte[] encrypt(@NotNull byte[] data, boolean finalChunk) throws VESException {
        return nativeEncrypt(nativeHandle, data, finalChunk);
    }

    public @NotNull byte[] decrypt(@NotNull byte[] data, boolean finalChunk) throws VESException {
        return nativeDecrypt(nativeHandle, data, finalChunk);
    }

    @Override
    public void close() {
        long h = nativeHandle;
        nativeHandle = 0;
        if (h != 0) nativeFree(h);
    }

    private static native @NotNull byte[] nativeEncrypt(long handle, @NotNull byte[] data, boolean finalChunk) throws VESException;
    private static native @NotNull byte[] nativeDecrypt(long handle, @NotNull byte[] data, boolean finalChunk) throws VESException;
    private static native @Nullable Object nativeGetMeta(long handle);
    private static native void nativeSetMeta(long vesHandle, @NotNull String uri,
                                              long cipherHandle, @NotNull Map<String, Object> meta) throws VESException;
    private static native void nativeFree(long handle);
}
