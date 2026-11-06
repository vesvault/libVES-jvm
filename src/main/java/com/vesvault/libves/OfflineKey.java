/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * A vault key held as PEM, used with no {@link Vault} and no network.
 *
 * <p>It decrypts an item encrypted to its public key: what {@code ves -Y KEY -i DATA}
 * makes, and what {@code ves -y KEY -I DATA} reads back. Its libVES context points the
 * API and poll URLs nowhere, as the ves CLI's offline mode does, so nothing done with
 * the key can reach the VES API.
 *
 * <p>Typical use: a key exported once with {@link Vault#privateKeyPEM()} while the API
 * was reachable, kept by the caller (encrypted, e.g. under an Android Keystore key),
 * and used here when the API is not.
 *
 * <p>Close it when done: {@link #close()} frees the native key and wipes its copy of
 * the PEM. Methods are synchronized; one instance may be shared between threads.
 */
public final class OfflineKey implements AutoCloseable {
    private long handle;

    private OfflineKey(long handle) {
        this.handle = handle;
    }

    /**
     * A key from its PEM private key: RSA or EC, or OQS (ML-KEM), as the PEM says.
     *
     * @param privatePEM the private key, PEM
     * @param veskey     the VESkey it is encrypted with, or null for a plain PEM
     */
    public static @NotNull OfflineKey fromPEM(@NotNull String privatePEM, @Nullable byte[] veskey) throws VESException {
        return new OfflineKey(nativeFromPEM(privatePEM, veskey));
    }

    /** The same, for a plain (unencrypted) PEM. */
    public static @NotNull OfflineKey fromPEM(@NotNull String privatePEM) throws VESException {
        return fromPEM(privatePEM, null);
    }

    /**
     * Decrypts one item encrypted to this key's public key.
     *
     * @param ciphertext the item ciphertext, as {@code ves -Ip} prints it
     * @return the plaintext. The caller owns it: wipe it when done.
     */
    public synchronized @NotNull byte[] decrypt(@NotNull String ciphertext) throws VESException {
        if (handle == 0) throw new IllegalStateException("OfflineKey is closed");
        return nativeDecrypt(handle, ciphertext.trim());
    }

    /** This key's public key, PEM, or null if libVES has none for it. */
    public synchronized @Nullable String publicKeyPEM() throws VESException {
        if (handle == 0) throw new IllegalStateException("OfflineKey is closed");
        return nativePublicKeyPEM(handle);
    }

    @Override
    public synchronized void close() {
        if (handle != 0) {
            nativeFree(handle);
            handle = 0;
        }
    }

    private static native long       nativeFromPEM(@NotNull String pem, @Nullable byte[] veskey) throws VESException;
    private static native byte[]     nativeDecrypt(long handle, @NotNull String ciphertext) throws VESException;
    private static native String     nativePublicKeyPEM(long handle) throws VESException;
    private static native void       nativeFree(long handle);

    static {
        System.loadLibrary("VESjni");
    }
}
