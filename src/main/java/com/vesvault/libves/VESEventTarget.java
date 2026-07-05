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

import java.util.concurrent.Executor;

/**
 * Real-time event source shared by {@link Vault} and {@link Item} — the Java
 * analog of {@code libVES.EventTarget} from libVES.js, where both
 * {@code libVES.Vault} and {@code libVES.Item} {@code extend EventTarget} and
 * events fire on the object itself.
 *
 * <p>You watch an object by subclassing it and overriding the {@code on…} hooks
 * you care about (all are empty no-ops by default), then calling {@link #start}:
 *
 * <pre>{@code
 * Vault vault = new Vault("ves://app/me@x.com") {
 *     @Override protected void onItemAdd(Event e)      { newMail(e.item()); }
 *     @Override protected void onSessionCreate(Event e) { newLogin(e); }
 * }.unlock(veskey);
 * vault.start();      // backfill nothing, long-poll for live events
 * ...
 * vault.stop();
 * }</pre>
 *
 * <p><b>Threading.</b> {@link #start} spawns one daemon worker thread that
 * long-polls the VES API on a <em>child</em> {@code libVES} context (so the
 * watched Vault's own connection stays usable). Hooks run on that worker thread
 * unless you set an {@link #dispatchOn(Executor) executor} (e.g. an Android main
 * thread {@code Handler::post}) to marshal them elsewhere.
 *
 * <p>A hook may call back into the watched {@link Vault}/{@link Item}: those
 * calls take the object's per-context monitor (see {@code Vault.ctxLock}), so
 * they serialize against operations the app drives on other threads rather than
 * racing the non-thread-safe native context. The hook still runs on the worker
 * (or {@link #dispatchOn(Executor) dispatch}) thread, so marshal any UI work
 * accordingly — the monitor only guards the native context, not your state.
 *
 * <p><b>Stopping.</b> {@link #stop} aborts the in-flight long-poll (via a curl
 * progress callback on the watch's child handle), so the worker exits within ~1s
 * rather than waiting out the {@link #pollSeconds(int)} window. {@link #close}
 * signals stop and joins the worker, which frees the native watch + child context
 * as it exits.
 */
public abstract class VESEventTarget implements AutoCloseable {

    /* Watch direction / mode flags — mirror LIBVES_W_* in Watch.h. */
    private static final int FLAG_REV  = 0x01;
    private static final int FLAG_POLL = 0x02;

    /* start() sentinel: begin from the current tail, replaying nothing. */
    private static final long FROM_NOW = Long.MIN_VALUE;

    /* Backoff between retries after a poll error, mirroring libVES.js (1s). */
    private static final long RETRY_MS = 1000;

    private volatile boolean running;
    private volatile Thread  worker;
    private volatile Executor executor;
    private volatile long    pollUsec = 30_000_000L;  /* 30s long-poll window */
    private volatile long    watchHandle;             /* libVES_Watch* (worker-owned) */

    /* ---- overridable hooks (the libVES.js on<type> set) ------------------- */

    /** Generic hook called for every event. The default decodes the type and
     *  fans out to the typed hooks below; override to intercept everything, and
     *  call {@code super.onEvent(e)} to keep the typed dispatch. */
    protected void onEvent(@NotNull Event e) {
        switch (e.object()) {
            case Event.OBJ_ENTRY:
                if (e.action() == Event.ACT_CREATED) {
                    if (e.itemType() == Item.TYPE_PASSWORD) onVaultAdd(e);
                    else onItemAdd(e);
                } else if (e.action() == Event.ACT_DELETED) {
                    onItemRemove(e);
                }
                break;
            case Event.OBJ_ITEM:
                switch (e.action()) {
                    case Event.ACT_CREATED:
                    case Event.ACT_LISTENING:  onItemUpdate(e); break;
                    case Event.ACT_DELETED:    onItemDelete(e); break;
                    default: break;
                }
                break;
            case Event.OBJ_KEY:
                if (e.action() == Event.ACT_LISTENING) onItemUpdate(e);
                break;
            case Event.OBJ_SESSION:
                if (e.action() == Event.ACT_CREATED) onSessionCreate(e);
                break;
            default:
                break;
        }
    }

    /** An item was shared into the watched vault. */
    protected void onItemAdd(@NotNull Event e) {}

    /** A new version of a watched item was written, or it signalled a change. */
    protected void onItemUpdate(@NotNull Event e) {}

    /** An item was unshared from the watched vault. */
    protected void onItemRemove(@NotNull Event e) {}

    /** A watched item was deleted. */
    protected void onItemDelete(@NotNull Event e) {}

    /** A sub-vault (password item referencing a secondary key) appeared. */
    protected void onVaultAdd(@NotNull Event e) {}

    /** A new session was created on the watched key/user. */
    protected void onSessionCreate(@NotNull Event e) {}

    /** A poll error, or an exception thrown by one of the hooks above. */
    protected void onError(@NotNull Exception e) {}

    /* ---- configuration --------------------------------------------------- */

    /**
     * Run the {@code on…} hooks on the given executor instead of the worker
     * thread — e.g. {@code target.dispatchOn(mainHandler::post)} on Android so
     * handlers can touch the UI. Set before {@link #start}.
     */
    public @NotNull VESEventTarget dispatchOn(Executor exec) {
        this.executor = exec;
        return this;
    }

    /**
     * Long-poll window in seconds (default 30). Also bounds how long
     * {@link #stop} / {@link #close} wait for the worker to notice the stop
     * request. Set before {@link #start}.
     */
    public @NotNull VESEventTarget pollSeconds(int seconds) {
        if (seconds <= 0) throw new IllegalArgumentException("seconds must be > 0");
        this.pollUsec = (long) seconds * 1_000_000L;
        return this;
    }

    /* ---- lifecycle ------------------------------------------------------- */

    /** Start watching from the current tail (no replay of past events). */
    public @NotNull VESEventTarget start() { return startAt(FROM_NOW); }

    /**
     * Start watching from an explicit position:
     * <ul>
     *   <li>{@code fromEventId >= 0} — deliver events with id ≥ {@code fromEventId}
     *       (history replay), then go live.</li>
     *   <li>{@code fromEventId < 0} — backfill the last {@code -fromEventId}
     *       events (delivered oldest-first), then go live.</li>
     * </ul>
     */
    public @NotNull VESEventTarget start(long fromEventId) { return startAt(fromEventId); }

    private synchronized VESEventTarget startAt(long pos) {
        Thread w = worker;
        if (w != null && w.isAlive())
            throw new IllegalStateException("watch already started");
        running = true;
        worker = new Thread(() -> runLoop(pos), "VESWatch");
        worker.setDaemon(true);
        worker.start();
        return this;
    }

    /** Request the watch to stop. Non-blocking; aborts the in-flight long-poll so the
     *  worker exits within ~1s (not the full poll window), then frees the native watch.
     *  Use {@link #close} (or {@link #join}) to wait for that. */
    public synchronized void stop() {
        running = false;
        long h = watchHandle;       /* synchronized vs the worker's finally; live => not yet freed */
        if (h != 0) nativeWatchAbort(h);
    }

    /** Block until the worker thread has fully stopped (bounded by the poll
     *  window). */
    public void join() throws InterruptedException {
        Thread w = worker;
        if (w != null) w.join();
    }

    /** Stop and wait for the worker to exit (freeing the native watch). Safe to
     *  call when never started. */
    @Override
    public void close() {
        stop();
        Thread w = worker;
        if (w != null) {
            try {
                w.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** True while the worker thread is running. */
    public boolean active() {
        Thread w = worker;
        return running && w != null && w.isAlive();
    }

    /* ---- worker ---------------------------------------------------------- */

    private void runLoop(long pos) {
        long watch = 0;
        try {
            watch = nativeCreateWatch();
            watchHandle = watch;
            nativeWatchSetPoll(watch, pollUsec);

            long next;
            if (pos == FROM_NOW) {
                Event[] probe = nativeWatchPoll(watch, 0, 1, FLAG_REV);
                next = probe.length > 0 ? probe[0].id + 1 : 0;
            } else if (pos < 0) {
                Event[] back = nativeWatchPoll(watch, 0, (int) (-pos), FLAG_REV);
                /* reverse load returns newest-first; deliver oldest-first */
                for (int i = back.length - 1; i >= 0; i--) deliver(back[i]);
                next = back.length > 0 ? maxId(back) + 1 : 0;
            } else {
                next = pos;
            }

            while (running) {
                Event[] batch;
                try {
                    batch = nativeWatchPoll(watch, next, 0, FLAG_POLL);
                } catch (VESException e) {
                    if (!running) break;
                    dispatchError(e);
                    try {
                        Thread.sleep(RETRY_MS);
                    } catch (InterruptedException ie) {
                        break;
                    }
                    continue;
                }
                if (batch.length > 0) {
                    for (Event e : batch) deliver(e);
                    next = maxId(batch) + 1;
                }
            }
        } catch (VESException e) {
            dispatchError(e);
        } finally {
            long h;
            synchronized (this) {   /* exclude stop()'s nativeWatchAbort: clear the handle
                                       before freeing so a concurrent stop can't abort a freed watch */
                h = watchHandle;
                watchHandle = 0;
            }
            if (h != 0) nativeWatchFree(h);
        }
    }

    private static long maxId(Event[] batch) {
        long m = 0;
        for (Event e : batch) if (e.id > m) m = e.id;
        return m;
    }

    private void deliver(Event e) {
        e.source = this;
        Executor ex = executor;
        if (ex != null) ex.execute(() -> dispatch(e));
        else dispatch(e);
    }

    private void dispatch(Event e) {
        try {
            onEvent(e);
        } catch (Exception ex) {
            safeOnError(ex);
        }
    }

    private void dispatchError(Exception e) {
        Executor ex = executor;
        if (ex != null) ex.execute(() -> safeOnError(e));
        else safeOnError(e);
    }

    private void safeOnError(Exception e) {
        try {
            onError(e);
        } catch (Exception ignored) {
            /* a throwing error handler must not take down the worker */
        }
    }

    /* ---- subclass plumbing ----------------------------------------------- */

    /** Build the native {@code libVES_Watch} for this object on a child context.
     *  Returns the watch handle; throws on a context that can't be watched yet
     *  (e.g. a locked vault). Implemented by {@link Vault} / {@link Item}. */
    abstract long nativeCreateWatch() throws VESException;

    /** The vault that event URIs resolve against — {@code this} for a Vault, the
     *  parent vault for an Item. */
    abstract @NotNull Vault ownerVault();

    /* ---- native (jni_watch.c) -------------------------------------------- */

    /** One long-poll cycle. Returns the events loaded (possibly empty); throws
     *  on a REST/connectivity error. Owns no state across calls beyond the
     *  watch handle's internal cursor. */
    private static native Event[] nativeWatchPoll(long watchHandle, long start, int count, int flags) throws VESException;

    private static native void nativeWatchSetPoll(long watchHandle, long usec);

    /** Signal the in-flight long-poll to abort so the worker exits promptly (instead of
     *  waiting out the poll window). */
    private static native void nativeWatchAbort(long watchHandle);

    /** Free the watch and its child {@code libVES} context. */
    private static native void nativeWatchFree(long watchHandle);
}
