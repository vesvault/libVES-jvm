/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A Vault Item.
 *
 * <p>Two construction modes:
 * <ul>
 *   <li><b>URI-backed</b> (lazy) — {@link Vault#item(String)}. {@link #nativeHandle}
 *       is 0; operations resolve the URI on each call via {@code libVES_VaultItem_loadFromURI}.
 *       Construction is free; no API round trip until a method is called.</li>
 *   <li><b>Native-backed</b> (eager-handle, lazy-value) — {@link Vault#password()}
 *       and (eventually) {@code items()}. {@link #nativeHandle} carries a REFUPped
 *       {@code libVES_VaultItem *}. id/type/meta/entries are already in memory;
 *       the encrypted value loads on first {@link #get} via an in-place swap.</li>
 * </ul>
 *
 * <p>Extends {@link VESEventTarget}: subclass and override {@code onItemUpdate} /
 * {@code onItemDelete} … then {@link VESEventTarget#start() start()} to watch
 * this one item's events in real time (mirrors {@code libVES.Item extends
 * libVES.EventTarget}).
 */
public class Item extends VESEventTarget {
    /** {@code libVES_VaultItem *} when native-backed; 0 for URI-backed. May be
     *  re-assigned by JNI on value-load swap — see {@code nativeGetVitem}. */
    long nativeHandle;
    @NotNull final Vault parent;
    @Nullable final String uri;

    public static final int TYPE_STRING   = 0;
    public static final int TYPE_FILE     = 1;
    public static final int TYPE_PASSWORD = 2;
    public static final int TYPE_SECRET   = 3;

    Item(@NotNull Vault parent, @NotNull String uri) {
        this.parent = parent;
        this.uri = uri;
    }

    /** Native-backed ctor — JNI hands a REFUPped {@code libVES_VaultItem *}.
     *  Package-private. */
    Item(@NotNull Vault parent, long vitemHandle) {
        this.parent = parent;
        this.uri = null;
        this.nativeHandle = vitemHandle;
    }

    public @NotNull byte[] get() throws VESException {
        synchronized (parent.ctxLock) {
            if (nativeHandle != 0) return nativeGetVitem();
            return nativeGet(parent.nativeHandle, uri);
        }
    }

    public @NotNull String getString() throws VESException {
        return new String(get(), StandardCharsets.UTF_8);
    }

    public void put(@NotNull byte[] value) throws VESException {
        synchronized (parent.ctxLock) {
            nativePut(parent.nativeHandle, uri, value, null);
        }
    }

    public void put(@NotNull String value) throws VESException {
        put(value.getBytes(StandardCharsets.UTF_8));
    }

    public void put(@NotNull byte[] value, @NotNull Iterable<String> shareUris) throws VESException {
        String[] arr = toArray(shareUris);
        synchronized (parent.ctxLock) {
            nativePut(parent.nativeHandle, uri, value, arr);
        }
    }

    public void put(@NotNull String value, @NotNull Iterable<String> shareUris) throws VESException {
        put(value.getBytes(StandardCharsets.UTF_8), shareUris);
    }

    /**
     * Create or replace this item with a raw {@code value} of an explicit
     * {@code type} ({@link #TYPE_STRING} … {@link #TYPE_SECRET}) and optional
     * cipher {@code meta}, shared to {@code shareUris}.
     *
     * <p>Unlike {@link #put} — which always writes a {@link #TYPE_STRING} item
     * with no metadata — this gives the caller control of the item type and meta.
     * It is the primitive for items whose value is a key interpreted by a cipher
     * named in the meta {@code "a"} tag (e.g. a {@link #TYPE_FILE} item with
     * {@code {"a":"VE"}}, which {@code libVES_VaultItem_getCipher} reads back).
     * The binding stays cipher-agnostic — the caller supplies the value bytes,
     * type, and meta. The value is wiped from native memory after the post; wipe
     * your own copy too if it is sensitive.
     */
    public void putRaw(@NotNull byte[] value, int type, @Nullable Map<String, Object> meta,
                       @NotNull Iterable<String> shareUris) throws VESException {
        String[] arr = toArray(shareUris);
        synchronized (parent.ctxLock) {
            nativePutRaw(parent.nativeHandle, uri, value, type, meta, arr);
        }
    }

    /**
     * Return the list of vaults this item is shared with. Each {@link Vault}
     * in the result wraps its own native {@code libVES *} and is
     * {@link AutoCloseable} — close them (or use try-with-resources on each)
     * when done.
     */
    public @NotNull List<Vault> share() throws VESException {
        String[] uris;
        synchronized (parent.ctxLock) {
            uris = nativeShare(parent.nativeHandle, uri);
        }
        List<Vault> result = new ArrayList<>(uris.length);
        for (String u : uris) result.add(new Vault(u));
        return result;
    }

    public void add(@NotNull Iterable<String> shareUris) throws VESException {
        String[] arr = toArray(shareUris);
        synchronized (parent.ctxLock) {
            nativeAdd(parent.nativeHandle, uri, arr);
        }
    }

    public void remove(@NotNull Iterable<String> shareUris) throws VESException {
        String[] arr = toArray(shareUris);
        synchronized (parent.ctxLock) {
            nativeRemove(parent.nativeHandle, uri, arr);
        }
    }

    /** Unshare from the parent vault. Equivalent to {@code remove([parent.uri()])}. */
    public void refuse() throws VESException {
        String pu = parent.uri();
        if (pu == null) throw new VESException(ErrorCode.PARAM,
            "Parent vault has no URI to unshare from", null);
        remove(java.util.Collections.singletonList(pu));
    }

    public void delete() throws VESException {
        synchronized (parent.ctxLock) {
            nativeDelete(parent.nativeHandle, uri);
        }
    }

    public boolean exists() throws VESException {
        synchronized (parent.ctxLock) {
            return nativeExists(parent.nativeHandle, uri);
        }
    }

    public boolean readable() {
        try {
            get();
            return true;
        } catch (VESException e) {
            return false;
        }
    }

    /**
     * Approximation: returns true when the parent vault is in this item's
     * share list. The libVES.js semantic is stricter ({@code owner || admin}
     * role) which requires fields the v1 share-list call does not surface;
     * presence-in-share-list is a reasonable lower bound.
     */
    public boolean writable() throws VESException {
        String myUri = parent.uri();
        if (myUri == null) return false;
        String want = myUri.endsWith("/") ? myUri : myUri + "/";
        try {
            for (Vault sh : share()) {
                try {
                    String su = sh.uri();
                    if (su != null) {
                        String norm = su.endsWith("/") ? su : su + "/";
                        if (norm.equals(want)) return true;
                    }
                } finally {
                    sh.close();
                }
            }
            return false;
        } catch (VESException e) {
            if (e.code == ErrorCode.NOT_FOUND) return true;
            if (e.code == ErrorCode.DENIED || e.code == ErrorCode.UNLOCK) return false;
            throw e;
        }
    }

    public @NotNull ItemCipher cipher() throws VESException {
        return cipher(null, null);
    }

    public @NotNull ItemCipher cipher(@Nullable String algo, @Nullable Iterable<String> shareUris) throws VESException {
        String[] arr = shareUris == null ? null : toArray(shareUris);
        long h;
        synchronized (parent.ctxLock) {
            h = nativeCipher(parent.nativeHandle, uri, algo, arr);
        }
        ItemCipher ic = new ItemCipher();
        ic.nativeHandle = h;
        ic.parent = this;
        return ic;
    }

    public @Nullable String uri() {
        return uri;
    }

    public long version() throws VESException {
        synchronized (parent.ctxLock) {
            return nativeVersion(parent.nativeHandle, uri);
        }
    }

    public int type() throws VESException {
        synchronized (parent.ctxLock) {
            return nativeType(parent.nativeHandle, uri);
        }
    }

    /** Watch this single item's events ({@code libVES_Watch_VaultItem_events})
     *  on a child context. Resolves the vitem from {@link #nativeHandle} when
     *  native-backed, else loads it from {@link #uri}. */
    @Override
    long nativeCreateWatch() throws VESException {
        synchronized (parent.ctxLock) {
            return nativeWatchItem(parent.nativeHandle, nativeHandle, uri);
        }
    }

    @Override
    @NotNull Vault ownerVault() { return parent; }

    @Override
    public void close() {
        super.close();   /* join the watch worker before taking the lock — see Vault.close */
        long h;
        synchronized (parent.ctxLock) {
            h = nativeHandle;
            nativeHandle = 0;
            if (h != 0) nativeFreeVitem(h);
        }
    }

    /* libVES vault-key URI parsing requires a trailing slash to disambiguate
     * the optional userRef segment ("ves://domain/extId/[userRef]"). Vault.uri()
     * canonicalizes without it (matching libVES.js); normalize on the way to
     * native so callers can pass either form. */
    private static @NotNull String[] toArray(@NotNull Iterable<String> it) {
        List<String> out = new ArrayList<>();
        for (String s : it) out.add(s.endsWith("/") ? s : s + "/");
        return out.toArray(new String[0]);
    }

    /** Instance method — reads {@link #nativeHandle} as a {@code libVES_VaultItem *}.
     *  Loads {@code vitem->value} if missing (fetch by id, REFDN old, REFUP new,
     *  re-assign {@link #nativeHandle} via JNI field write). */
    private native @NotNull byte[] nativeGetVitem() throws VESException;

    /** Static, package-private. REFDNs the {@code libVES_VaultItem *}. */
    static native void nativeFreeVitem(long vitemHandle);

    private static native @NotNull byte[] nativeGet(long vesHandle, @NotNull String uri) throws VESException;
    private static native void nativePut(long vesHandle, @NotNull String uri,
                                         @NotNull byte[] value,
                                         @Nullable String[] shareUris) throws VESException;
    private static native void nativePutRaw(long vesHandle, @NotNull String uri,
                                            @NotNull byte[] value, int type, @Nullable Object meta,
                                            @NotNull String[] shareUris) throws VESException;
    private static native boolean nativeExists(long vesHandle, @NotNull String uri) throws VESException;
    private static native void    nativeDelete(long vesHandle, @NotNull String uri) throws VESException;
    private static native String[] nativeShare(long vesHandle, @NotNull String uri) throws VESException;
    private static native void     nativeAdd(long vesHandle, @NotNull String uri,
                                              @NotNull String[] shareUris) throws VESException;
    private static native void     nativeRemove(long vesHandle, @NotNull String uri,
                                                 @NotNull String[] shareUris) throws VESException;
    private static native long     nativeVersion(long vesHandle, @NotNull String uri) throws VESException;
    private static native int      nativeType(long vesHandle, @NotNull String uri) throws VESException;
    private static native long     nativeCipher(long vesHandle, @NotNull String uri,
                                                 @Nullable String algo,
                                                 @Nullable String[] shareUris) throws VESException;
    private static native long     nativeWatchItem(long vesHandle, long vitemHandle,
                                                   @Nullable String uri) throws VESException;
}
