package org.garmin.hfpprototype;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.media.AudioAttributes;
import android.media.AudioDeviceInfo;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.provider.DocumentsContract;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/** All MediaPlayer access and provider I/O stay on its one worker looper, including release. */
final class AsyncPlayer {
    interface Listener {
        void onPrepared(AsyncPlayer player);
        void onRoute(AsyncPlayer player, boolean reported, boolean exactSco);
        void onAudible(AsyncPlayer player);
        void onTerminal(AsyncPlayer player, String safeReason, Throwable error);
        void onReleased(AsyncPlayer player);
    }

    private static final PlayerLoadLease LOAD_SLOT = new PlayerLoadLease();
    static boolean isBusy() { return LOAD_SLOT.busy(); }
    static AsyncPlayer create(String token, long loadingDeadline, Handler main, Listener listener) {
        PlayerLoadLease.Ticket ticket = LOAD_SLOT.tryAcquire(token, loadingDeadline);
        if (ticket == null) return null;
        try { return new AsyncPlayer(token, ticket, main, listener); }
        catch (RuntimeException | Error error) { LOAD_SLOT.releaseAfterCleanup(ticket); throw error; }
    }

    final String token;
    private final PlayerLoadLease.Ticket ticket;
    private final Handler main;
    private final Listener listener;
    private final HandlerThread thread;
    private final Handler worker;
    private final AtomicBoolean checkQueued = new AtomicBoolean();
    // These fields are confined to worker; main uses only commands and immutable route snapshots.
    private MediaPlayer media;
    private String selectedAddress;
    private boolean closed;
    private boolean started;
    private boolean audible;
    private boolean documentCleanupFailed;
    private long playbackDeadline;

    private AsyncPlayer(String token, PlayerLoadLease.Ticket ticket, Handler main, Listener listener) {
        this.token = token;
        this.ticket = ticket;
        this.main = main;
        this.listener = listener;
        thread = new HandlerThread("Garmin-local-media");
        thread.start();
        try { worker = new Handler(thread.getLooper()); }
        catch (RuntimeException | Error error) { thread.quitSafely(); throw error; }
    }

    boolean accepts(String sessionToken) { return ticket.matches(sessionToken, ticket); }

    void load(Context app, Uri source, AudioAttributes attributes, AudioDeviceInfo sco, String address) {
        worker.post(() -> {
            if (!ticket.allowsLoading(SystemClock.elapsedRealtime())) { releaseWorker(); return; }
            selectedAddress = address;
            try {
                loadWorker(app, source, attributes, sco);
                if (!ticket.allowsLoading(SystemClock.elapsedRealtime())) releaseWorker();
            } catch (RuntimeException | IOException error) {
                terminal("media-load-error", error);
            }
        });
    }

    private void loadWorker(Context app, Uri source, AudioAttributes attributes, AudioDeviceInfo sco)
            throws IOException {
        checkDocumentWorker(app, source);
        if (!ticket.allowsLoading(SystemClock.elapsedRealtime())) return;
        AssetFileDescriptor descriptor = app.getContentResolver().openAssetFileDescriptor(source, "r");
        try {
            // This open can remain blocked forever. Stop changes the ticket without waiting for it.
            if (!ticket.allowsLoading(SystemClock.elapsedRealtime())) return;
            if (descriptor == null) throw new IOException();
            final MediaPlayer candidate = new MediaPlayer();
            media = candidate;
            candidate.setAudioAttributes(attributes);
            if (!candidate.setPreferredDevice(sco)) throw new IllegalStateException();
            candidate.setOnPreparedListener(prepared -> {
                if (closed || media != candidate) return;
                if (!ticket.allowsLoading(SystemClock.elapsedRealtime())) { releaseWorker(); return; }
                main.post(() -> listener.onPrepared(this)); // No start from provider/prepared callback.
            });
            candidate.setOnErrorListener((failed, what, extra) -> {
                if (!closed && media == candidate) {
                    terminal("media-error-" + what + "-" + extra, null);
                }
                return true;
            });
            candidate.setOnCompletionListener(completed -> {
                if (!closed && media == candidate) terminal("media-completed", null);
            });
            candidate.addOnRoutingChangedListener(router -> {
                if (!closed && media == candidate && started) inspectWorkerRoute();
            }, worker);
            // FileDescriptor overload avoids any URI/network fallback and still stays off main.
            long length = descriptor.getLength();
            if (length == AssetFileDescriptor.UNKNOWN_LENGTH) {
                if (descriptor.getStartOffset() != 0) throw new IOException();
                candidate.setDataSource(descriptor.getFileDescriptor());
            } else {
                candidate.setDataSource(descriptor.getFileDescriptor(), descriptor.getStartOffset(), length);
            }
            // Native setDataSource may also block; a late result is disposed before prepare/start.
            if (!ticket.allowsLoading(SystemClock.elapsedRealtime())) return;
            candidate.prepareAsync();
        } finally {
            if (descriptor != null) {
                try { descriptor.close(); }
                catch (IOException | RuntimeException error) {
                    // Do not allow a new owner when descriptor cleanup cannot be established.
                    documentCleanupFailed = true;
                    throw error;
                }
            }
        }
    }

    /** Provider query, cursor access and close share the existing bounded player job, never main. */
    private void checkDocumentWorker(Context app, Uri source) {
        if (!DocumentsContract.isDocumentUri(app, source)) throw new IllegalArgumentException();
        if (!ticket.allowsLoading(SystemClock.elapsedRealtime())) return;
        Cursor cursor = app.getContentResolver().query(source,
                new String[] { DocumentsContract.Document.COLUMN_FLAGS }, null, null, null);
        try {
            // A canceled or late provider result cannot authorize a file open or player creation.
            if (!ticket.allowsLoading(SystemClock.elapsedRealtime())) return;
            if (cursor == null || !cursor.moveToFirst()
                    || (cursor.getInt(0) & DocumentsContract.Document.FLAG_VIRTUAL_DOCUMENT) != 0) {
                throw new IllegalArgumentException();
            }
        } finally {
            if (cursor != null) {
                try { cursor.close(); }
                catch (RuntimeException error) {
                    documentCleanupFailed = true;
                    throw error;
                }
            }
        }
    }

    /** Main has checked the current session, active Call route and production gate before this command. */
    void startMuted(long deadlineElapsedMs) {
        worker.post(() -> {
            if (closed || !accepts(token) || media == null || started) { releaseWorker(); return; }
            if (SystemClock.elapsedRealtime() >= deadlineElapsedMs) {
                terminal("media-start-deadline", null);
                return;
            }
            try {
                playbackDeadline = deadlineElapsedMs;
                media.setVolume(0f, 0f);
                media.start();
                started = true;
                worker.post(poll);
            } catch (RuntimeException error) { terminal("media-start-error", error); }
        });
    }

    /** Recheck actual SCO on the owning looper before unmuting; queued old commands cannot authorize it. */
    void allowAudible() {
        worker.post(() -> {
            if (closed || !accepts(token) || media == null || !started) { releaseWorker(); return; }
            if (SystemClock.elapsedRealtime() >= playbackDeadline) { terminal("media-playback-deadline", null); return; }
            try {
                if (!isExactSco(media.getRoutedDevice())) { terminal("media-route-before-unmute-mismatch", null); return; }
                if (audible) return;
                media.setVolume(0.5f, 0.5f);
                audible = true;
                // Stop can race a native volume call; promptly dispose after it if cancellation won.
                if (!accepts(token)) { releaseWorker(); return; }
                main.post(() -> listener.onAudible(this));
            } catch (RuntimeException error) { terminal("media-unmute-error", error); }
        });
    }

    void requestRouteCheck() {
        if (!accepts(token) || !checkQueued.compareAndSet(false, true)) return;
        if (!worker.post(() -> { checkQueued.set(false); if (started && !closed) inspectWorkerRoute(); })) {
            checkQueued.set(false);
        }
    }

    /** Nonblocking main-side invalidation. Never calls MediaPlayer or joins the blocked worker. */
    void stop() {
        ticket.cancel();
        worker.postAtFrontOfQueue(this::releaseWorker);
    }

    private boolean isExactSco(AudioDeviceInfo route) {
        return route != null && route.isSink() && route.getType() == AudioDeviceInfo.TYPE_BLUETOOTH_SCO
                && selectedAddress != null && !selectedAddress.isEmpty()
                && selectedAddress.equalsIgnoreCase(route.getAddress());
    }

    private void inspectWorkerRoute() {
        if (closed || !started || media == null) return;
        if (!accepts(token)) { releaseWorker(); return; }
        try {
            AudioDeviceInfo route = media.getRoutedDevice();
            boolean reported = route != null;
            boolean exact = isExactSco(route);
            main.post(() -> listener.onRoute(this, reported, exact));
            if ((reported && !exact) || (!reported && audible)) {
                terminal("media-actual-route-lost", null);
            }
        } catch (RuntimeException error) { terminal("media-route-error", error); }
    }

    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (closed) return;
            if (!accepts(token)) { releaseWorker(); return; }
            long remaining = playbackDeadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) { terminal("media-playback-deadline", null); return; }
            inspectWorkerRoute();
            if (!closed) worker.postDelayed(this, Math.min(100, remaining));
        }
    };

    private void terminal(String reason, Throwable error) {
        if (closed) return;
        main.post(() -> listener.onTerminal(this, reason, error));
        releaseWorker();
    }

    private void releaseWorker() {
        if (closed) return;
        closed = true;
        ticket.cancel();
        worker.removeCallbacksAndMessages(null);
        MediaPlayer releasing = media;
        media = null;
        boolean released = !documentCleanupFailed;
        try {
            if (releasing != null) {
                if (started) {
                    try { releasing.setVolume(0f, 0f); } catch (RuntimeException ignored) { }
                }
                releasing.release(); // Same worker as creation and every other MediaPlayer operation.
            }
        } catch (RuntimeException error) {
            released = false;
            main.post(() -> listener.onTerminal(this, "media-release-error", error));
        } finally {
            selectedAddress = null;
            // Failed document or player cleanup keeps the process slot busy.
            if (released) LOAD_SLOT.releaseAfterCleanup(ticket);
            thread.quitSafely();
            if (released) main.post(() -> listener.onReleased(this));
        }
    }
}
