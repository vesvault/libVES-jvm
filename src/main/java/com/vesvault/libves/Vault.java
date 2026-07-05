/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES-jvm:        Java bindings for libVES.c
 *    \__ /     \ __/
 *       \\     //
 *        \\   //              - Key Management and Exchange
 *         \\_//               - Item Encryption and Sharing
 *         /   \
 *         \___/
 *
 *
 * (c) 2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the accompanying LICENSE
 * file, or at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 ***************************************************************************/
package com.vesvault.libves;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * The primary VES object. Wraps a native {@code libVES *} instance.
 *
 * <p>Modeled on {@code libVES.subtle()} from libVES.js. Each Vault represents
 * a single VES vault identified by a {@code ves://} URI.
 *
 * <p>Sub-vaults are created via {@link #vault(String)} and share context with
 * their parent through {@code libVES_child}: the child gets its own
 * {@code libVES *} (independent curl handle, error state, session token copy)
 * with REFUPed shares of the parent's external/vaultKey/me/propagators. The
 * vault-key identity of a child is held in {@link #vaultKeyHandle} — operations
 * like {@link #password()}, {@link #items()}, {@link #vaults()} dispatch
 * through that handle when non-zero, or fall back to
 * {@code libVES_getVaultKey(libves)} when zero (the root-after-unlock case).
 *
 * <p>Extends {@link VESEventTarget}: subclass and override {@code onItemAdd} …
 * then {@link VESEventTarget#start() start()} to watch this vault's events in
 * real time (mirrors {@code libVES.Vault extends libVES.EventTarget}).
 *
 * <p><b>Thread safety.</b> A native {@code libVES *} context (its libcurl easy
 * handle, OpenSSL and error state) is <em>not</em> thread-safe, so every native
 * call that touches one runs under that context's {@link #ctxLock}. This is what
 * makes the {@link VESEventTarget} watch safe: its hooks fire on a worker thread
 * and routinely call back into the watched Vault/Item while the app drives the
 * same Vault elsewhere — without serialization those two collide on the shared
 * context and crash the process. Callers therefore do not need to funnel libVES
 * calls onto a single thread themselves; they only need to keep the (blocking)
 * calls off whatever thread must stay responsive.
 */
public class Vault extends VESEventTarget {
    long nativeHandle;       /* libVES * — every Vault owns one. */
    long vaultKeyHandle;     /* libVES_VaultKey * — 0 for root (use libVES->vaultKey), owned for child. */

    /**
     * Serializes access to this Vault's native {@code libVES *} context. Held for
     * the duration of each native call made here, on this Vault's {@link Item}s
     * (which operate on {@code parent.nativeHandle}) and on their
     * {@link ItemCipher}s — so at most one native call is ever in flight per
     * context. Reentrant, so a libVES call that nests another on the same Vault
     * is fine.
     *
     * <p>Each Vault owns its own context, so child and sub-vaults (and the
     * watch's own child context) get their own monitor and serialize
     * independently of their parent — the parent's lock is never held across the
     * watch's up-to-30s long-poll. {@link #close()} deliberately joins the watch
     * worker <em>before</em> taking this lock: a hook may be mid-call awaiting
     * it, and holding it across the join would deadlock.
     */
    final Object ctxLock = new Object();

    /**
     * Optional one-time library initialization. Sets the application name sent
     * in the {@code User-Agent} header.
     */
    public static void init(@Nullable String appName) {
        nativeInit(appName);
    }

    /**
     * Open a Vault for the given URI. Accepts {@code ves://domain/externalId}
     * or just {@code "domain"}.
     */
    public Vault(@NotNull String uri) throws VESException {
        this.nativeHandle = nativeNew(uri);
    }

    /** Called from JNI ({@link #nativeChildVaults}) to wrap a child {@code libVES *}
     *  + {@code libVES_VaultKey *} pair. Package-private. */
    Vault(long libves, long vaultKey) {
        this.nativeHandle = libves;
        this.vaultKeyHandle = vaultKey;
    }

    /**
     * Run a native initializer on this Vault's underlying {@code libVES *}.
     * {@code fnPtr} must be a {@code void (*)(libVES *)} cast to {@code long}
     * — typically obtained from a JNI getter in the library that defines it
     * (e.g. {@code VESmail_tls_initVES}). Used to wire TLS trust, API/WWW
     * URLs, or {@code httpInitFn} from another native component.
     *
     * <p>Call after construction and before {@link #unlock} so the setup is
     * in place before the first REST request.
     */
    public @NotNull Vault initFn(long fnPtr) {
        synchronized (ctxLock) {
            if (nativeHandle != 0 && fnPtr != 0) nativeInitFn(nativeHandle, fnPtr);
        }
        return this;
    }

    /**
     * Attach a server session bearer token to this Vault. The token is sent
     * as {@code Authorization: Bearer …} on every libVES REST request. Pass
     * {@code null} to clear. Use in flows that have a session token already
     * (e.g. a saved-VESkey unlock recovered from VESlocker) and want to skip
     * the full unlock-to-derive-session path.
     */
    public @NotNull Vault sessionToken(@Nullable String token) {
        synchronized (ctxLock) {
            if (nativeHandle != 0) nativeSetSessionToken(nativeHandle, token);
        }
        return this;
    }

    /** The current session bearer token, or null. */
    public @Nullable String sessionToken() {
        synchronized (ctxLock) {
            return nativeHandle == 0 ? null : nativeGetSessionToken(nativeHandle);
        }
    }

    /**
     * A configurable option on this Vault's native {@code libVES *} context.
     *
     * <p>Most entries map straight onto a {@code libVES_setOption} call
     * ({@code LIBVES_O_*}); {@link #TLS_ROOT} is the one exception — it is not a
     * libVES option but a convenience that installs a libVES {@code httpInitFn}
     * pointing the bundled libcurl at a PEM CA bundle.
     *
     * <p>Each constant carries a stable wire {@code code} switched on by the JNI
     * layer (NOT the {@code LIBVES_O_*} ordinal, so the libVES.h enum can be
     * reordered without touching Java) and a {@link Kind} that selects the
     * value type. Keep the codes in sync with {@code jni_vault.c}.
     */
    public enum Option {
        /** API base URL ({@code LIBVES_O_APIURL}) — e.g. a sandbox backend. */
        API_URL(1, Kind.STRING),
        /** WWW base URL ({@code LIBVES_O_WWWURL}). */
        WWW_URL(2, Kind.STRING),
        /** Long-poll base URL ({@code LIBVES_O_POLLURL}). */
        POLL_URL(3, Kind.STRING),
        /** User-Agent app name ({@code LIBVES_O_APPNAME}). */
        APP_NAME(4, Kind.STRING),
        /**
         * Path to a PEM CA bundle for the statically-linked libcurl
         * ({@code CURLOPT_CAINFO}, via a libVES {@code httpInitFn}). Needed where
         * libcurl has no system CA path (e.g. Android) and the API TLS handshake
         * would otherwise fail. Not a {@code libVES_setOption}.
         */
        TLS_ROOT(5, Kind.STRING),
        /** Debug verbosity ({@code LIBVES_O_DEBUG}); 0 = off. */
        DEBUG(6, Kind.INT),
        /** Generated-veskey length ({@code LIBVES_O_VESKEYLEN}). */
        VESKEY_LEN(7, Kind.INT),
        /** Session timeout in seconds ({@code LIBVES_O_SESSTMOUT}). */
        SESSION_TIMEOUT(8, Kind.INT);

        enum Kind { STRING, INT }

        final int code;
        final Kind kind;
        Option(int code, Kind kind) { this.code = code; this.kind = kind; }
    }

    /**
     * Set a string-valued {@link Option} (URLs, app name, {@link Option#TLS_ROOT
     * TLS_ROOT}). Set after construction and before the first REST call; chainable.
     *
     * @throws IllegalArgumentException if {@code opt} expects an integer value
     */
    public @NotNull Vault setOption(@NotNull Option opt, @NotNull String value) {
        if (opt.kind != Option.Kind.STRING)
            throw new IllegalArgumentException(opt + " takes an int value, not a String");
        synchronized (ctxLock) {
            if (nativeHandle != 0) nativeSetOptionStr(nativeHandle, opt.code, value);
        }
        return this;
    }

    /**
     * Set an integer-valued {@link Option} ({@link Option#DEBUG DEBUG},
     * {@link Option#VESKEY_LEN VESKEY_LEN}, {@link Option#SESSION_TIMEOUT
     * SESSION_TIMEOUT}). Chainable.
     *
     * @throws IllegalArgumentException if {@code opt} expects a string value
     */
    public @NotNull Vault setOption(@NotNull Option opt, long value) {
        if (opt.kind != Option.Kind.INT)
            throw new IllegalArgumentException(opt + " takes a String value, not an int");
        synchronized (ctxLock) {
            if (nativeHandle != 0) nativeSetOptionInt(nativeHandle, opt.code, value);
        }
        return this;
    }

    /** Convenience for boolean {@link Option}s (e.g. {@link Option#DEBUG}). */
    public @NotNull Vault setOption(@NotNull Option opt, boolean value) {
        return setOption(opt, value ? 1L : 0L);
    }

    public @NotNull Vault unlock(@NotNull String veskey) throws VESException {
        return unlock(veskey.getBytes(StandardCharsets.UTF_8));
    }

    public @NotNull Vault unlock(@NotNull byte[] veskey) throws VESException {
        synchronized (ctxLock) {
            nativeUnlock(nativeHandle, veskey);
        }
        return this;
    }

    /**
     * Create a new SECONDARY (app) vault key for this Vault's external
     * reference, locked under {@code veskey}, and post it.
     *
     * <p>The native call elevates this Vault's session before posting via
     * {@code libVES_refreshSession} on the libVES context's currently-set
     * vaultKey (the parent's UNLOCKED primary, inherited from
     * {@link #subVault(String, String)}). Without elevation the server
     * 403s the POST.
     *
     * <p>Calling this directly on a freshly-opened Vault (no parent context
     * with an unlocked primary) throws — open via
     * {@code parent.subVault(domain, externalId)} after the parent has done
     * its {@code setVESkey} for the primary.
     */
    public @NotNull Vault setVESkey(@NotNull byte[] veskey) throws VESException {
        synchronized (ctxLock) {
            nativeSetVESkey(nativeHandle, veskey);
        }
        return this;
    }

    /**
     * Create or rotate the user's PRIMARY vault key using an HTTP basic-auth
     * temp password ({@code passwd}) — the recovery_token landed via the
     * VESlocker OTP exchange in the signup chain, or any equivalent
     * elevated-auth credential. Mirrors
     * {@code ves-www/inc/passwd.html.php#vv_passwd_rekey}.
     *
     * <p>{@code lostId == 0} → fresh primary; signup path.
     * <br>{@code lostId  > 0} → rotation: server demotes that vault key id to
     * type=lost on the same request.
     *
     * <p>On success the Vault's session token is replaced with the freshly
     * issued one (decryptable from the response's {@code encSessionToken} via
     * the new key); read it back via {@link #sessionToken()} and pass it on
     * to the next signup step (appKey + ves_backup write-back).
     *
     * <p>The username for basic auth is taken from the Vault's user
     * ({@code ves->me->email}), populated from the {@code ves:////email}
     * primary-vault URI form by the {@link Vault#Vault(String)} constructor.
     * Open this Vault with that URI before calling.
     */
    public @NotNull Vault setVESkey(@NotNull byte[] veskey, long lostId, @NotNull String passwd) throws VESException {
        synchronized (ctxLock) {
            nativeSetVESkeyPrimary(nativeHandle, veskey, lostId, passwd);
        }
        return this;
    }

    public boolean unlocked() {
        synchronized (ctxLock) {
            return nativeHandle != 0 && nativeUnlocked(nativeHandle);
        }
    }

    public void lock() {
        synchronized (ctxLock) {
            if (nativeHandle != 0) nativeLock(nativeHandle);
        }
    }

    public @NotNull Item item(@NotNull String uri) throws VESException {
        return new Item(this, uri);
    }

    public @NotNull Item item(@NotNull String domain, @NotNull String externalId) throws VESException {
        return item("ves://" + domain + "/" + externalId);
    }

    public @NotNull List<Item> items() throws VESException {
        String[] uris;
        synchronized (ctxLock) {
            uris = nativeItems(nativeHandle);
        }
        List<Item> result = new java.util.ArrayList<>(uris.length);
        for (String u : uris) result.add(new Item(this, u));
        return result;
    }

    /**
     * Sub-vaults of this Vault — one {@link Vault} per password-typed vault
     * item whose entry references a secondary vault key. Each result shares
     * context with {@code this} via {@code libVES_child}; close each (or
     * {@code try-with-resources}) when done.
     */
    public @NotNull List<Vault> vaults() throws VESException {
        Vault[] arr;
        synchronized (ctxLock) {
            arr = nativeChildVaults(nativeHandle, vaultKeyHandle);
        }
        return arr == null ? List.of() : Arrays.asList(arr);
    }

    /**
     * Open a sub-Vault for the given URI within this Vault's context. The
     * child has its own {@code libVES *} (cloned via {@code libVES_child}) and
     * a freshly fetched {@code libVES_VaultKey *} for the URI's identity.
     * The child's decryption chains through this Vault's unlocked state, so
     * the parent must be unlocked (or carry a usable session token) before
     * calling.
     */
    public @NotNull Vault vault(@NotNull String uri) throws VESException {
        // The child is cloned from (and fetches its key through) this Vault's
        // context, so hold the parent lock across the whole derivation.
        synchronized (ctxLock) {
            long childLibves = nativeChild(nativeHandle);
            if (childLibves == 0) throw new VESException(ErrorCode.INTERNAL, "libVES_child failed", null);
            try {
                long vk = nativeFetchVaultKey(childLibves, uri);
                return new Vault(childLibves, vk);
            } catch (VESException e) {
                nativeFree(childLibves);
                throw e;
            }
        }
    }

    public @NotNull Vault vault(@NotNull String domain, @NotNull String externalId) throws VESException {
        return vault("ves://" + domain + "/" + externalId);
    }

    /**
     * Open a child Vault targeted at a (domain, externalId) reference
     * without fetching a vault key — for the "secondary doesn't exist yet,
     * we're about to create it" case ({@link #setVESkey(byte[])} on the
     * returned child). The child inherits this Vault's UNLOCKED state via
     * {@code libVES_child}, so a parent that just ran {@link
     * #setVESkey(byte[], long, String) setVESkey-for-primary} carries the
     * new primary into the child — exactly what the child needs for the
     * elevation step inside its own {@code setVESkey}.
     *
     * <p>Unlike {@link #vault(String, String)} this does not call
     * {@code libVES_VaultKey_get2} — the server would 404 since the secondary
     * has not been posted yet.
     */
    public @NotNull Vault subVault(@NotNull String domain, @NotNull String externalId) throws VESException {
        long child;
        synchronized (ctxLock) {
            child = nativeSubVault(nativeHandle, domain, externalId);
        }
        if (child == 0) throw new VESException(ErrorCode.INTERNAL, "subVault returned null", null);
        return new Vault(child, 0);
    }

    /** The vault key id (server-side id of the underlying {@code libVES_VaultKey}).
     *  Returns 0 if the vault key isn't loaded yet (root before unlock). */
    public long version() {
        synchronized (ctxLock) {
            return nativeHandle == 0 ? 0 : nativeVaultKeyId(nativeHandle, vaultKeyHandle);
        }
    }

    /** The user id of this vault's owner. For a root Vault without an unlocked
     *  vault key, falls back to {@code libVES_me} (requires a session token). */
    public long userId() {
        synchronized (ctxLock) {
            return nativeHandle == 0 ? 0 : nativeUserId(nativeHandle, vaultKeyHandle);
        }
    }

    /**
     * The password Vault Item associated with this Vault's vault key. The
     * returned {@link Item} is native-backed (carries a REFUPped
     * {@code libVES_VaultItem *}); the first {@link Item#get} loads + decrypts
     * the value and caches it on the same vitem.
     */
    public @NotNull Item password() throws VESException {
        long vi;
        synchronized (ctxLock) {
            vi = nativePassword(nativeHandle, vaultKeyHandle);
        }
        return new Item(this, vi);
    }

    /** Generate a random biased-ASCII veskey of the default length (32). */
    public @NotNull String random() {
        return nativeRandom(0);
    }

    public @NotNull String random(int length) {
        if (length <= 0) throw new IllegalArgumentException("length must be > 0");
        return nativeRandom(length);
    }

    public @Nullable String uri() {
        synchronized (ctxLock) {
            return nativeHandle == 0 ? null : nativeUri(nativeHandle);
        }
    }

    public @Nullable String domain() {
        synchronized (ctxLock) {
            return nativeHandle == 0 ? null : nativeDomain(nativeHandle);
        }
    }

    public @Nullable String externalId() {
        synchronized (ctxLock) {
            return nativeHandle == 0 ? null : nativeExternalId(nativeHandle);
        }
    }

    /**
     * Heuristic: treat as owned unless the externalId starts with {@code !}
     * (anonymous-vault marker, per libVES.js convention).
     */
    public boolean isOwner() {
        String xid = externalId();
        return xid != null && !xid.startsWith("!");
    }

    /** True once {@link #unlock} has succeeded and the vault key is loaded. */
    public boolean isCurrent() {
        return unlocked();
    }

    /** Watch this vault's vault-key events ({@code libVES_Watch_VaultKey_events},
     *  falling back to {@code _User_events} when no key is loaded) on a child
     *  context. Requires the vault to be unlocked or carry a usable session
     *  token. */
    @Override
    long nativeCreateWatch() throws VESException {
        synchronized (ctxLock) {
            return nativeWatchVault(nativeHandle, vaultKeyHandle);
        }
    }

    @Override
    @NotNull Vault ownerVault() { return this; }

    @Override
    public void close() {
        super.close();   /* stop the watch + join its worker BEFORE taking ctxLock:
                            a hook may be mid-call awaiting the lock (deadlock). */
        long vk, h;
        synchronized (ctxLock) {
            vk = vaultKeyHandle;
            h = nativeHandle;
            vaultKeyHandle = 0;
            nativeHandle = 0;
            if (vk != 0) nativeFreeVaultKey(vk);
            if (h != 0) nativeFree(h);
        }
    }

    private static native void    nativeInit(@Nullable String appName);
    private static native long    nativeNew(@NotNull String uri) throws VESException;
    private static native long    nativeChild(long handle);
    private static native long    nativeFetchVaultKey(long handle, @NotNull String uri) throws VESException;
    private static native void    nativeFreeVaultKey(long vkHandle);
    private static native long    nativeVaultKeyId(long handle, long vkHandle);
    private static native long    nativeUserId(long handle, long vkHandle);
    private static native void    nativeInitFn(long handle, long fnPtr);
    private static native void    nativeSetSessionToken(long handle, @Nullable String token);
    private static native String  nativeGetSessionToken(long handle);
    private static native void    nativeSetOptionStr(long handle, int code, @NotNull String value);
    private static native void    nativeSetOptionInt(long handle, int code, long value);
    private static native void    nativeUnlock(long handle, @NotNull byte[] veskey) throws VESException;
    private static native void    nativeSetVESkey(long handle, @NotNull byte[] veskey) throws VESException;
    private static native long    nativeSubVault(long handle, @NotNull String domain, @NotNull String externalId) throws VESException;
    private static native void    nativeSetVESkeyPrimary(long handle, @NotNull byte[] veskey, long lostId, @NotNull String passwd) throws VESException;
    private static native boolean nativeUnlocked(long handle);
    private static native void    nativeLock(long handle);
    private static native void    nativeFree(long handle);
    private static native String  nativeRandom(int length);
    private static native String  nativeUri(long handle);
    private static native String  nativeDomain(long handle);
    private static native String  nativeExternalId(long handle);
    private static native String[] nativeItems(long handle) throws VESException;
    private static native long     nativePassword(long handle, long vkHandle) throws VESException;
    private static native Vault[]  nativeChildVaults(long handle, long vkHandle) throws VESException;
    private static native long      nativeWatchVault(long handle, long vkHandle) throws VESException;

    static {
        System.loadLibrary("VESjni");
    }
}
