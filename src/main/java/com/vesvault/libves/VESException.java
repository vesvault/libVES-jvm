/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/** Thrown for any libVES error. {@link #code} mirrors {@code LIBVES_E_*}. */
public class VESException extends Exception {
    public final @NotNull ErrorCode code;
    public final @Nullable String detail;

    /** Called from JNI. */
    @SuppressWarnings("unused")
    VESException(int codeOrdinal, @Nullable String message, @Nullable String detail) {
        super(message != null ? message : ErrorCode.fromOrdinal(codeOrdinal).name());
        this.code = ErrorCode.fromOrdinal(codeOrdinal);
        this.detail = detail;
    }

    public VESException(@NotNull ErrorCode code, @Nullable String message, @Nullable String detail) {
        super(message != null ? message : code.name());
        this.code = code;
        this.detail = detail;
    }
}
