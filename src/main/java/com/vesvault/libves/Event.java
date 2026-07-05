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

/**
 * A single VES event delivered to a {@link VESEventTarget} ({@link Vault} or
 * {@link Item}) that is being watched. Immutable value object — marshaled from
 * the native {@code libVES_Event} at the JNI boundary, so it holds no native
 * pointer and outlives the underlying watch poll cycle.
 *
 * <p>{@link #type()} packs an <em>object</em> and an <em>action</em> nibble,
 * mirroring {@code LIBVES_EO_*} / {@code LIBVES_EA_*} from {@code Event.h}.
 * {@link VESEventTarget#onEvent} decodes them via {@link #object()} /
 * {@link #action()} to fan out to the typed {@code onItemAdd} … hooks; most
 * consumers override those and never inspect {@code type()} directly.
 */
public final class Event {
    /* Object nibble — (type >> 4) & 0xf. Mirrors LIBVES_EO_* >> 4. */
    public static final int OBJ_USER    = 0x1;
    public static final int OBJ_KEY     = 0x2;
    public static final int OBJ_ITEM    = 0x3;
    public static final int OBJ_SESSION = 0x4;
    public static final int OBJ_ENTRY   = 0x5;
    public static final int OBJ_DOMAIN  = 0x6;

    /* Action nibble — type & 0xf. Mirrors LIBVES_EA_*. */
    public static final int ACT_CREATED   = 0x1;
    public static final int ACT_UPDATED   = 0x2;
    public static final int ACT_DELETED   = 0x3;
    public static final int ACT_LOST      = 0x4;
    public static final int ACT_LISTENING = 0x5;
    public static final int ACT_PENDING   = 0x6;

    final long   id;
    final int    type;
    final long   recordedAtUsec;
    final String itemUri;
    final int    itemType;
    final String vaultKeyUri;
    final String userEmail;
    final String creatorEmail;
    final long   sessionId;
    final String sessionRemote;
    final String sessionUserAgent;

    /** The watched object this event was dispatched on. Set by
     *  {@link VESEventTarget} before dispatch; lets {@link #item()} resolve URIs
     *  against the right vault. */
    VESEventTarget source;

    /** Called from JNI (jni_watch.c) — keep the parameter order in sync with the
     *  constructor lookup there. */
    @SuppressWarnings("unused")
    Event(long id, int type, long recordedAtUsec,
          @Nullable String itemUri, int itemType,
          @Nullable String vaultKeyUri,
          @Nullable String userEmail, @Nullable String creatorEmail,
          long sessionId, @Nullable String sessionRemote, @Nullable String sessionUserAgent) {
        this.id = id;
        this.type = type;
        this.recordedAtUsec = recordedAtUsec;
        this.itemUri = itemUri;
        this.itemType = itemType;
        this.vaultKeyUri = vaultKeyUri;
        this.userEmail = userEmail;
        this.creatorEmail = creatorEmail;
        this.sessionId = sessionId;
        this.sessionRemote = sessionRemote;
        this.sessionUserAgent = sessionUserAgent;
    }

    /** Server-assigned monotonic event id within the watched stream. */
    public long id() { return id; }

    /** Raw packed type ({@code object << 4 | action}). */
    public int type() { return type; }

    /** The object nibble — one of {@code OBJ_*}. */
    public int object() { return (type >> 4) & 0xf; }

    /** The action nibble — one of {@code ACT_*}. */
    public int action() { return type & 0xf; }

    /** When the event was recorded, in milliseconds since the epoch (0 if unset). */
    public long recordedAt() { return recordedAtUsec / 1000; }

    /** URI of the vault item this event concerns, or null for non-item events. */
    public @Nullable String itemUri() { return itemUri; }

    /** The vault item's type ({@link Item#TYPE_STRING} … {@link Item#TYPE_SECRET}),
     *  or -1 when the event carries no item. A {@link Item#TYPE_PASSWORD} item in
     *  a user-vault watch is a sub-vault — routed to {@code onVaultAdd}. */
    public int itemType() { return itemType; }

    /**
     * The affected item as a URI-backed {@link Item} resolved against the
     * watched vault, or null when this event carries no item. Cheap — no API
     * round trip until you call a method on the returned Item.
     */
    public @Nullable Item item() {
        if (itemUri == null || source == null) return null;
        /* URI-backed Item ctor (package-private, no API round trip) — avoids the
         * checked-throws wrapper Vault.item(String). */
        return new Item(source.ownerVault(), itemUri);
    }

    /** URI of the vault key tied to this event (the watched key, or a sharer's
     *  key for item watches), or null. */
    public @Nullable String vaultKeyUri() { return vaultKeyUri; }

    /** Best-effort author email: the creator if known, else the acting user. */
    public @Nullable String authorEmail() {
        return creatorEmail != null ? creatorEmail : userEmail;
    }

    /** Session id for {@code session.created} events, else 0. */
    public long sessionId() { return sessionId; }

    /** Remote address of the session ({@code session.created}), or null. */
    public @Nullable String sessionRemote() { return sessionRemote; }

    /** User-agent of the session ({@code session.created}), or null. */
    public @Nullable String sessionUserAgent() { return sessionUserAgent; }

    @Override
    public @NotNull String toString() {
        return "Event#" + id + "(" + Integer.toHexString(type)
            + (itemUri != null ? " " + itemUri : "") + ")";
    }
}
