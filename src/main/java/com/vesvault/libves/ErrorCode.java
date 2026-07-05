/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves;

import org.jetbrains.annotations.NotNull;

/** Mirrors {@code LIBVES_E_*} from libVES.h. */
public enum ErrorCode {
    OK(0),
    PARAM(1),
    CONN(2),
    PARSE(3),
    CRYPTO(4),
    UNLOCK(5),
    DENIED(6),
    NOT_FOUND(7),
    SERVER(8),
    UNSUPPORTED(9),
    INCORRECT(10),
    ASSERT(11),
    DIALOG(12),
    QUOTA(13),
    INTERNAL(31);

    public final int value;

    ErrorCode(int value) { this.value = value; }

    public static @NotNull ErrorCode fromOrdinal(int code) {
        for (ErrorCode e : values()) if (e.value == code) return e;
        return INTERNAL;
    }
}
