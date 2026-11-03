package org.garmin.hfpprototype;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;

/** Production admission/ownership policy. A timeout revokes authority, not an outstanding proxy. */
public final class HfpPreflightLease {
    public static final long TIMEOUT_MS = 8_000;
    public static final long SNAPSHOT_MAX_AGE_MS = 2_000;
    private final AtomicReference<Ticket> owner = new AtomicReference<>();
    private final AtomicBoolean cleanupFault = new AtomicBoolean();

    public Ticket tryAcquire(String sessionId, String selectedIdentity, long nowMs) {
        if (sessionId == null || sessionId.isEmpty() || selectedIdentity == null
                || selectedIdentity.isEmpty() || nowMs < 0 || nowMs > Long.MAX_VALUE - TIMEOUT_MS) {
            throw new IllegalArgumentException();
        }
        Ticket ticket = new Ticket(sessionId, selectedIdentity, nowMs);
        if (cleanupFault.get()) return null;
        return owner.compareAndSet(null, ticket) ? ticket : null;
    }

    public boolean busy() { return cleanupFault.get() || owner.get() != null; }
    public boolean isCleanupFaulted() { return cleanupFault.get(); }
    /** A late, additional proxy whose close failed cannot be hidden by an already-released ticket. */
    public void cleanupFailed() { cleanupFault.set(true); }

    /** Consume at most one before-call observation. Android's profile result is not an audio route. */
    public boolean admit(Ticket ticket, String sessionId, String selectedIdentity,
                         boolean permissionGranted, boolean selectedStillBonded,
                         boolean selectedConnected, int exactSelectedListMatches,
                         long observedAtMs, long nowMs) {
        if (ticket == null || owner.get() != ticket || !ticket.identifies(sessionId, selectedIdentity)) {
            return false; // A foreign/old callback cannot revoke the actual owner.
        }
        if (cleanupFault.get() || !permissionGranted || !selectedStillBonded || !selectedConnected
                || exactSelectedListMatches != 1 || observedAtMs < ticket.createdAtMs
                || observedAtMs > nowMs || nowMs >= ticket.deadlineMs
                || nowMs - observedAtMs > SNAPSHOT_MAX_AGE_MS) {
            ticket.cancel();
            return false;
        }
        return ticket.state.compareAndSet(0, 2);
    }

    /** Caller must have closed every acquired proxy (or know the request was never issued). */
    public boolean releaseAfterCleanup(Ticket ticket) {
        if (ticket == null || owner.get() != ticket) return false;
        ticket.cancel();
        return owner.compareAndSet(ticket, null);
    }

    public static final class Ticket {
        private final String sessionId;
        private final String selectedIdentity;
        private final long createdAtMs;
        private final long deadlineMs;
        // 0 pending, 1 canceled, 2 consumed. Do not include identity in logs/toString.
        private final AtomicInteger state = new AtomicInteger();
        private Ticket(String sessionId, String selectedIdentity, long nowMs) {
            this.sessionId = sessionId;
            this.selectedIdentity = selectedIdentity;
            createdAtMs = nowMs;
            deadlineMs = nowMs + TIMEOUT_MS;
        }
        public boolean identifies(String session, String selected) {
            return sessionId.equals(session) && selectedIdentity.equals(selected);
        }
        public boolean allowsObservation(long nowMs) {
            return state.get() == 0 && nowMs >= createdAtMs && nowMs < deadlineMs;
        }
        public void cancel() { state.set(1); }
        public long deadlineMs() { return deadlineMs; }
    }
}
