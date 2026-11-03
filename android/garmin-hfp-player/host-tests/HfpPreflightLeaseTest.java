package org.garmin.hfpprototype;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Admission/ownership controls use production policy; no Android proxy, Binder, or hardware is executed. */
public final class HfpPreflightLeaseTest {
    private static final List<String> cases = new ArrayList<>();
    private static void require(boolean value, String why) { if (!value) throw new AssertionError(why); }
    private static void check(String name, Runnable action) { action.run(); cases.add(name); }
    private static boolean admit(HfpPreflightLease lease, HfpPreflightLease.Ticket ticket,
                                  String session, String selected, long observed, long now) {
        return lease.admit(ticket, session, selected, true, true, true, 1, observed, now);
    }

    public static void main(String[] args) {
        check("selected-connected-snapshot-is-one-shot", () -> {
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
            require(admit(lease, ticket, "one", "chosen", 101, 102), "fresh selected profile admitted");
            require(!admit(lease, ticket, "one", "chosen", 103, 104), "duplicate result cannot create another call");
            require(lease.busy(), "admission does not prove resources freed");
            require(lease.releaseAfterCleanup(ticket), "owner freed only on cleanup");
        });
        check("never-callback-timeout-retains-one-request-owner", () -> {
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
            require(!ticket.allowsObservation(8_100), "deadline is inclusive");
            ticket.cancel();
            require(lease.busy() && lease.tryAcquire("two", "chosen", 9_000) == null,
                    "no callback means no close evidence and no accumulating request");
            require(!admit(lease, ticket, "one", "chosen", 9_000, 9_001), "late connected state is not a call");
        });
        check("cancel-then-late-close-allows-new-session-without-old-call", () -> {
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket old = lease.tryAcquire("one", "chosen", 100);
            old.cancel();
            require(!admit(lease, old, "one", "chosen", 101, 102), "canceled callback cannot admit");
            require(lease.tryAcquire("two", "chosen", 103) == null, "late proxy still outstanding");
            require(lease.releaseAfterCleanup(old), "controlled late proxy closed");
            HfpPreflightLease.Ticket current = lease.tryAcquire("two", "chosen", 104);
            require(current != null, "cleanup enables a later explicit attempt");
            PlaybackGate gate = new PlaybackGate();
            require(gate.start("two", 104), "new call policy owns new token");
            long deadline = gate.deadlineMs();
            require(!admit(lease, old, "one", "chosen", 105, 106)
                    && !lease.releaseAfterCleanup(old), "old result and old cleanup denied");
            require(gate.state() == PlaybackGate.State.WAITING_FOR_ANSWER
                    && gate.deadlineMs() == deadline && current.allowsObservation(106),
                    "old result changes neither the new ticket nor call policy");
            require(admit(lease, current, "two", "chosen", 105, 106), "new request still admissible");
        });
        check("token-device-and-ticket-identities-all-required", () -> {
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
            HfpPreflightLease.Ticket foreign = new HfpPreflightLease().tryAcquire("one", "chosen", 100);
            require(!admit(lease, ticket, "old-session", "chosen", 101, 102), "wrong token denied");
            require(!admit(lease, ticket, "one", "other-device", 101, 102), "wrong selected identity denied");
            require(!admit(lease, foreign, "one", "chosen", 101, 102), "same labels do not confer ownership");
            require(admit(lease, ticket, "one", "chosen", 101, 102), "foreign results leave current admission intact");
        });
        check("bonded-or-other-connected-device-is-insufficient", () -> {
            // These cover different mismatches between the two profile observations, not arbitrary counts.
            for (int scenario = 0; scenario < 4; scenario++) {
                HfpPreflightLease lease = new HfpPreflightLease();
                HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
                boolean bonded = scenario != 0;
                boolean selectedConnected = scenario != 1;
                int exactSelectedMatches = scenario == 2 ? 0 : scenario == 3 ? 2 : 1;
                require(!lease.admit(ticket, "one", "chosen", true, bonded, selectedConnected,
                        exactSelectedMatches, 101, 102), "unbonded/disconnected/absent/duplicated selection denied");
                require(!admit(lease, ticket, "one", "chosen", 103, 104), "failed attempt cannot be revived");
            }
        });
        check("permission-denial-never-admits-or-frees-a-proxy", () -> {
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
            require(!lease.admit(ticket, "one", "chosen", false, true, true, 1, 101, 102),
                    "CONNECT permission required despite previously connected result");
            require(lease.busy() && lease.tryAcquire("two", "chosen", 103) == null, "resource still needs close");
            require(lease.releaseAfterCleanup(ticket) && !lease.busy(), "successful close recovers the owner");
        });
        check("snapshot-age-future-time-and-request-deadline-are-separate", () -> {
            long[][] bad = {{101, 2_102}, {103, 102}, {99, 102}, {8_099, 8_100}};
            for (long[] times : bad) {
                HfpPreflightLease lease = new HfpPreflightLease();
                HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
                require(!admit(lease, ticket, "one", "chosen", times[0], times[1]),
                        "stale/future/pre-request/deadline result denied");
            }
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
            require(admit(lease, ticket, "one", "chosen", 101, 2_101), "exact snapshot age limit accepted");
        });
        check("cancel-while-controlled-profile-query-waits-denies-late-admission", () -> {
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch returned = new CountDownLatch(1);
            AtomicBoolean admitted = new AtomicBoolean();
            AtomicBoolean workerFailed = new AtomicBoolean();
            Thread worker = new Thread(() -> {
                entered.countDown();
                try {
                    if (!returned.await(3, TimeUnit.SECONDS)) throw new AssertionError("controlled query timed out");
                    admitted.set(admit(lease, ticket, "one", "chosen", 101, 102));
                } catch (Throwable failure) { workerFailed.set(true); }
                finally { lease.releaseAfterCleanup(ticket); }
            });
            worker.setDaemon(true);
            worker.start();
            try {
                require(entered.await(3, TimeUnit.SECONDS), "query waiting");
                ticket.cancel();
                require(returned.getCount() == 1 && lease.busy(), "Stop revokes while query remains blocked");
                require(lease.tryAcquire("two", "chosen", 103) == null, "no second query worker admitted");
            } catch (InterruptedException error) { throw new AssertionError(error); }
            finally {
                returned.countDown();
                try { worker.join(3_000); } catch (InterruptedException error) { throw new AssertionError(error); }
            }
            require(!worker.isAlive() && !workerFailed.get() && !admitted.get() && !lease.busy(),
                    "late result disposed and controlled cleanup completed, without admission");
        });
        check("failed-close-keeps-process-busy-even-after-a-late-extra-proxy", () -> {
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
            ticket.cancel();
            lease.cleanupFailed();
            require(lease.busy() && lease.tryAcquire("two", "chosen", 103) == null, "failed close forbids retry");
            require(lease.releaseAfterCleanup(ticket), "remaining known ticket can be retired");
            require(lease.busy() && lease.tryAcquire("two", "chosen", 104) == null,
                    "retirement cannot erase another unclosed platform proxy");
        });
        check("unexpected-extra-proxy-before-first-cleanup-completes-revokes-admission", () -> {
            HfpPreflightLease lease = new HfpPreflightLease();
            HfpPreflightLease.Ticket ticket = lease.tryAcquire("one", "chosen", 100);
            // Production records this fault immediately on a distinct second proxy callback,
            // before the first close result reaches the admission callback. No close failure needed.
            ticket.cancel();
            lease.cleanupFailed();
            require(!admit(lease, ticket, "one", "chosen", 101, 102),
                    "otherwise-valid first connected snapshot cannot create a call");
            require(lease.tryAcquire("two", "chosen", 103) == null, "extra proxy pending forbids request");
            require(lease.releaseAfterCleanup(ticket), "first known proxy close can retire its ticket");
            require(lease.isCleanupFaulted() && lease.busy()
                    && lease.tryAcquire("two", "chosen", 104) == null,
                    "first close result is not proof of all platform callbacks/cleanup");
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
