package org.garmin.hfpprototype;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Tests production ownership/cancellation only; controlled latches are not Android/provider execution. */
public final class PlayerLoadLeaseTest {
    private static final List<String> cases = new ArrayList<>();
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    private static void check(String name, Runnable action) { action.run(); cases.add(name); }
    private static void await(CountDownLatch latch) {
        try { require(latch.await(3, TimeUnit.SECONDS), "controlled worker did not reach checkpoint"); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new AssertionError(error); }
    }
    private static void join(Thread thread) {
        try { thread.join(3_000); require(!thread.isAlive(), "controlled worker did not exit"); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new AssertionError(error); }
    }

    public static void main(String[] args) {
        check("empty-session-id-rejected", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            boolean thrown = false;
            try { lease.tryAcquire("", 20_000); } catch (IllegalArgumentException expected) { thrown = true; }
            require(thrown && !lease.busy(), "invalid ID cannot occupy slot");
        });
        check("one-outstanding-load-only", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlayerLoadLease.Ticket first = lease.tryAcquire("one", 20_000);
            require(first != null && lease.busy(), "owns slot");
            require(lease.tryAcquire("two", 20_000) == null, "no second worker/resource owner");
            require(lease.releaseAfterCleanup(first), "cleanup releases first");
        });
        check("session-and-player-identity-both-required", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlayerLoadLease.Ticket first = lease.tryAcquire("one", 20_000);
            PlayerLoadLease.Ticket foreign = new PlayerLoadLease().tryAcquire("one", 20_000);
            require(first.matches("one", first), "correct identity");
            require(!first.matches("two", first), "wrong session");
            require(!first.matches("one", foreign), "same token is not another player's identity");
        });
        check("loading-deadline-inclusive", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlayerLoadLease.Ticket ticket = lease.tryAcquire("one", 20_000);
            require(ticket.allowsLoading(19_999), "before deadline");
            require(!ticket.allowsLoading(20_000) && !ticket.allowsLoading(30_000), "late result not prepared");
            require(lease.busy(), "deadline cannot pretend blocked resources have been freed");
        });
        check("cancel-denies-all-later-load-and-player-results", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlayerLoadLease.Ticket ticket = lease.tryAcquire("one", 20_000);
            ticket.cancel();
            ticket.cancel();
            require(ticket.isCanceled(), "cancellation is visible and idempotent");
            require(!ticket.allowsLoading(1) && !ticket.matches("one", ticket), "no late authority");
        });
        check("cancel-keeps-slot-busy-until-real-cleanup", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlayerLoadLease.Ticket ticket = lease.tryAcquire("one", 20_000);
            ticket.cancel();
            require(lease.busy() && lease.tryAcquire("two", 30_000) == null, "no unbounded retries");
            require(lease.releaseAfterCleanup(ticket) && !lease.busy(), "worker cleanup finally releases slot");
            require(lease.tryAcquire("two", 30_000) != null, "next attempt allowed after cleanup");
        });
        check("stale-cleanup-cannot-free-new-owner", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlayerLoadLease.Ticket first = lease.tryAcquire("one", 20_000);
            require(lease.releaseAfterCleanup(first), "old cleaned");
            PlayerLoadLease.Ticket second = lease.tryAcquire("two", 40_000);
            require(!lease.releaseAfterCleanup(first), "old cleanup ignored");
            require(lease.busy() && second.matches("two", second), "new owner unchanged");
            require(!first.matches("one", first), "released old callback is invalid");
        });
        check("foreign-cleanup-cannot-cancel-another-lease", () -> {
            PlayerLoadLease firstLease = new PlayerLoadLease();
            PlayerLoadLease secondLease = new PlayerLoadLease();
            PlayerLoadLease.Ticket first = firstLease.tryAcquire("one", 20_000);
            PlayerLoadLease.Ticket second = secondLease.tryAcquire("two", 20_000);
            require(!secondLease.releaseAfterCleanup(first), "foreign cleanup refused");
            require(first.matches("one", first) && second.matches("two", second), "neither owner altered");
        });
        check("concurrent-acquisition-has-one-winner", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger winners = new AtomicInteger();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                final int index = i;
                Thread thread = new Thread(() -> {
                    try { await(start); if (lease.tryAcquire("job-" + index, 20_000) != null) winners.incrementAndGet(); }
                    catch (Throwable error) { failure.compareAndSet(null, error); }
                });
                thread.setDaemon(true);
                threads.add(thread);
                thread.start();
            }
            start.countDown();
            for (Thread thread : threads) join(thread);
            require(failure.get() == null && winners.get() == 1 && lease.busy(), "atomic single slot");
        });
        check("stop-remains-processable-while-controlled-provider-is-blocked", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlayerLoadLease.Ticket ticket = lease.tryAcquire("one", 20_000);
            PlaybackGate gate = new PlaybackGate();
            gate.start("one", 0); gate.answer("one", 1); gate.confirmCallRoute("one", true, 2);
            gate.beginPrepare("one", 3);
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch providerReturn = new CountDownLatch(1);
            AtomicBoolean resourceClosed = new AtomicBoolean();
            AtomicBoolean preparedOrStarted = new AtomicBoolean();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread worker = new Thread(() -> {
                try {
                    entered.countDown();
                    await(providerReturn); // Controlled stand-in for a synchronous blocking open.
                    if (ticket.allowsLoading(10)) preparedOrStarted.set(true);
                } catch (Throwable error) { failure.set(error); }
                finally { resourceClosed.set(true); lease.releaseAfterCleanup(ticket); }
            });
            worker.setDaemon(true);
            worker.start();
            await(entered);
            try {
                require(gate.stop("one", "visible-Stop"), "main-side policy can stop while open waits");
                ticket.cancel(); // No join/provider call in production cancellation.
                require(providerReturn.getCount() == 1 && worker.isAlive(), "open still blocked");
                require(gate.state() == PlaybackGate.State.STOPPED && lease.busy(), "UI ended, resources still owned");
                require(lease.tryAcquire("two", 40_000) == null, "retry busy refusal while blocked");
            } finally { providerReturn.countDown(); join(worker); }
            require(failure.get() == null && resourceClosed.get() && !preparedOrStarted.get(), "late resource disposed without prepare/start");
            require(!lease.busy(), "only actual worker cleanup freed slot");
        });
        check("prepare-timeout-cancels-pending-load-before-late-result", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlaybackGate gate = new PlaybackGate();
            gate.start("one", 0); gate.answer("one", 1); gate.confirmCallRoute("one", true, 2);
            gate.beginPrepare("one", 3);
            PlayerLoadLease.Ticket ticket = lease.tryAcquire("one", gate.deadlineMs());
            require(!gate.tick("one", 20_003), "main gate enforces prepare deadline independent of loader");
            ticket.cancel();
            require(!ticket.allowsLoading(20_004) && !gate.preparedMuted("one", 20_004), "late prepare cannot start");
            require(lease.busy(), "timed out provider is still owned");
            require(lease.releaseAfterCleanup(ticket), "late worker cleanup");
        });
        check("new-session-gate-is-unchanged-by-old-ticket-result", () -> {
            PlayerLoadLease lease = new PlayerLoadLease();
            PlayerLoadLease.Ticket first = lease.tryAcquire("one", 20_000);
            first.cancel(); lease.releaseAfterCleanup(first);
            PlaybackGate gate = new PlaybackGate();
            gate.start("two", 30_000);
            long deadline = gate.deadlineMs();
            PlayerLoadLease.Ticket second = lease.tryAcquire("two", 50_000);
            require(!first.matches("two", second) && !gate.preparedMuted("one", 30_001), "old result denied twice");
            require(gate.state() == PlaybackGate.State.WAITING_FOR_ANSWER && gate.deadlineMs() == deadline,
                    "new session and deadline untouched");
        });
        StringBuilder names = new StringBuilder();
        for (String name : cases) {
            if (names.length() > 0) names.append(',');
            names.append('"').append(name).append('"');
        }
        System.out.println("{\"all_passed\":true,\"host_cases\":" + cases.size()
                + ",\"cases\":[" + names + "],\"Android_runtime\":false,\"device_IO\":false}");
    }
}
