package org.garmin.hfpprototype;

/** Android-free state machine used by the actual session. All time is monotonic milliseconds. */
public final class PlaybackGate {
    public enum State {
        IDLE, WAITING_FOR_ANSWER, WAITING_FOR_ROUTE, READY,
        PREPARING, VERIFYING_MUTED, PLAYING, STOPPED
    }

    public static final long ANSWER_TIMEOUT_MS = 60_000;
    public static final long ROUTE_TIMEOUT_MS = 20_000;
    public static final long PLAY_LIMIT_MS = 10_000;
    public static final long MUTED_VERIFY_TIMEOUT_MS = 2_000;
    private String sessionId;
    private State state = State.IDLE;
    private long deadline;
    private long playbackDeadline;
    private String stopReason = "";

    public boolean start(String id, long now) {
        if (id == null || id.isEmpty() || (state != State.IDLE && state != State.STOPPED)) {
            return false;
        }
        // Session IDs must be freshly generated; a stopped ID cannot be resurrected.
        if (id.equals(sessionId)) return false;
        sessionId = id;
        state = State.WAITING_FOR_ANSWER;
        deadline = now + ANSWER_TIMEOUT_MS;
        playbackDeadline = 0;
        stopReason = "";
        return true;
    }

    public boolean answer(String id, long now) {
        if (!live(id, now) || state != State.WAITING_FOR_ANSWER) return false;
        state = State.WAITING_FOR_ROUTE;
        deadline = now + ROUTE_TIMEOUT_MS;
        return true;
    }

    /** Initial unrelated routes are tolerated only while waiting; confirmed-route loss is terminal. */
    public boolean confirmCallRoute(String id, boolean matchesSelectedDevice, long now) {
        if (!live(id, now)) return false;
        if (state == State.WAITING_FOR_ANSWER) return false;
        if (!matchesSelectedDevice) {
            if (state != State.WAITING_FOR_ROUTE) stop(id, "call-route-lost");
            return false;
        }
        if (state == State.WAITING_FOR_ROUTE) {
            state = State.READY;
            // An unattended answered call must also end if Play is never pressed.
            deadline = now + ANSWER_TIMEOUT_MS;
        }
        return true;
    }

    public boolean beginPrepare(String id, long now) {
        if (!live(id, now) || state != State.READY) return false;
        state = State.PREPARING;
        deadline = now + ROUTE_TIMEOUT_MS;
        return true;
    }

    /** Start the player at volume zero; ten seconds include this verification period. */
    public boolean preparedMuted(String id, long now) {
        if (!live(id, now) || state != State.PREPARING) return false;
        state = State.VERIFYING_MUTED;
        playbackDeadline = now + PLAY_LIMIT_MS;
        deadline = now + MUTED_VERIFY_TIMEOUT_MS;
        return true;
    }

    /** Must represent actual player SCO identity, never a requested/preferred route. */
    public boolean confirmPlayerRoute(String id, boolean matchesSelectedDevice, long now) {
        if (!live(id, now)) return false;
        if (state != State.VERIFYING_MUTED && state != State.PLAYING) return false;
        if (!matchesSelectedDevice) {
            stop(id, "player-route-mismatch");
            return false;
        }
        if (state == State.VERIFYING_MUTED) {
            state = State.PLAYING;
            deadline = playbackDeadline;
        }
        return true;
    }

    public boolean stop(String id, String reason) {
        if (!isCurrent(id) || state == State.IDLE || state == State.STOPPED) return false;
        state = State.STOPPED;
        deadline = 0;
        stopReason = reason == null ? "stopped" : reason;
        return true;
    }

    /** Returns true while the supplied session is live; a stale token cannot expire a new session. */
    public boolean tick(String id, long now) {
        if (!isCurrent(id) || state == State.IDLE || state == State.STOPPED) return false;
        if (now >= deadline) {
            stop(id, state.name().toLowerCase(java.util.Locale.ROOT) + "-timeout");
            return false;
        }
        return true;
    }

    private boolean live(String id, long now) { return tick(id, now); }
    public boolean isCurrent(String id) { return id != null && id.equals(sessionId); }
    public State state() { return state; }
    public String stopReason() { return stopReason; }
    public long deadlineMs() { return deadline; }
}
