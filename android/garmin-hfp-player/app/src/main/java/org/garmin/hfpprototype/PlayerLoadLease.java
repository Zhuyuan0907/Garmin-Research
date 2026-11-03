package org.garmin.hfpprototype;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Production load ownership, independent of Android. Cancel never calls/waits for the provider. */
public final class PlayerLoadLease {
    private final AtomicReference<Ticket> owner = new AtomicReference<>();

    public Ticket tryAcquire(String sessionId, long loadingDeadlineMs) {
        if (sessionId == null || sessionId.isEmpty()) throw new IllegalArgumentException();
        Ticket ticket = new Ticket(sessionId, loadingDeadlineMs);
        return owner.compareAndSet(null, ticket) ? ticket : null;
    }

    public boolean busy() { return owner.get() != null; }

    /** Only call after the worker has closed its resources; cancellation alone does not free the slot. */
    public boolean releaseAfterCleanup(Ticket ticket) {
        if (ticket == null || owner.get() != ticket) return false;
        ticket.cancel();
        return owner.compareAndSet(ticket, null);
    }

    public static final class Ticket {
        private final String sessionId;
        private final long loadingDeadlineMs;
        private final AtomicBoolean canceled = new AtomicBoolean();
        private Ticket(String sessionId, long deadline) {
            this.sessionId = sessionId;
            loadingDeadlineMs = deadline;
        }
        public void cancel() { canceled.set(true); }
        public boolean isCanceled() { return canceled.get(); }
        public boolean matches(String session, Ticket playerIdentity) {
            return this == playerIdentity && sessionId.equals(session) && !isCanceled();
        }
        public boolean allowsLoading(long nowMs) {
            return !isCanceled() && nowMs < loadingDeadlineMs;
        }
    }
}
