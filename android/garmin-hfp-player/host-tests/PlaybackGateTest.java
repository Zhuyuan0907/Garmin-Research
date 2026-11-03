package org.garmin.hfpprototype;

import java.util.ArrayList;
import java.util.List;

/** Host tests of the production gate; no Android objects, mocked Bluetooth, or audio execution. */
public final class PlaybackGateTest {
    private static final List<String> cases = new ArrayList<>();
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    private static void check(String name, Runnable action) {
        action.run();
        cases.add(name);
    }
    private static PlaybackGate waiting() {
        PlaybackGate g = new PlaybackGate();
        require(g.start("one", 1_000), "start");
        return g;
    }
    private static PlaybackGate ready() {
        PlaybackGate g = waiting();
        require(g.answer("one", 1_001), "answer");
        require(g.confirmCallRoute("one", true, 1_002), "route");
        return g;
    }
    private static PlaybackGate muted() {
        PlaybackGate g = ready();
        require(g.beginPrepare("one", 1_003), "prepare");
        require(g.preparedMuted("one", 2_000), "prepared at volume zero");
        return g;
    }
    private static PlaybackGate playing() {
        PlaybackGate g = muted();
        require(g.confirmPlayerRoute("one", true, 2_001), "actual player route");
        return g;
    }
    public static void main(String[] args) {
        check("play-before-answer-denied", () -> {
            PlaybackGate g = waiting();
            require(!g.beginPrepare("one", 1_001), "not answered");
            require(!g.confirmPlayerRoute("one", true, 1_002), "player cannot bypass call");
            require(g.state() == PlaybackGate.State.WAITING_FOR_ANSWER, "waiting");
        });
        check("answered-without-selected-call-route-denied", () -> {
            PlaybackGate g = waiting();
            g.answer("one", 1_001);
            require(!g.beginPrepare("one", 1_002), "no selected endpoint");
        });
        check("unrelated-initial-call-route-not-authority", () -> {
            PlaybackGate g = waiting();
            g.answer("one", 1_001);
            require(!g.confirmCallRoute("one", false, 1_002), "wrong endpoint");
            require(!g.beginPrepare("one", 1_003), "still cannot play");
            require(g.confirmCallRoute("one", true, 1_004), "later selected endpoint");
        });
        check("actual-player-route-required-before-unmute", () -> {
            PlaybackGate g = muted();
            require(g.state() == PlaybackGate.State.VERIFYING_MUTED, "remains muted");
            require(g.confirmPlayerRoute("one", true, 2_001), "matching actual route");
            require(g.state() == PlaybackGate.State.PLAYING, "permit unmute");
        });
        check("actual-player-mismatch-terminal", () -> {
            PlaybackGate g = muted();
            require(!g.confirmPlayerRoute("one", false, 2_001), "wrong actual route");
            require(g.state() == PlaybackGate.State.STOPPED, "terminal");
            require(!g.confirmPlayerRoute("one", true, 2_002), "late recovery not automatic");
        });
        check("call-route-loss-stops-audible-playback", () -> {
            PlaybackGate g = playing();
            require(!g.confirmCallRoute("one", false, 2_002), "route loss");
            require(g.state() == PlaybackGate.State.STOPPED, "stopped");
        });
        check("player-route-loss-stops-audible-playback", () -> {
            PlaybackGate g = playing();
            require(!g.confirmPlayerRoute("one", false, 2_002), "player rerouted");
            require(g.state() == PlaybackGate.State.STOPPED, "stopped");
        });
        check("sixty-second-unanswered-deadline-inclusive", () -> {
            PlaybackGate g = waiting();
            require(g.tick("one", 60_999), "before deadline");
            require(!g.answer("one", 61_000), "late answer denied");
            require(g.state() == PlaybackGate.State.STOPPED, "timeout");
        });
        check("twenty-second-route-deadline-inclusive", () -> {
            PlaybackGate g = waiting();
            g.answer("one", 1_001);
            require(!g.confirmCallRoute("one", true, 21_001), "late route denied");
            require(g.state() == PlaybackGate.State.STOPPED, "timeout");
        });
        check("answered-but-never-played-call-expires", () -> {
            PlaybackGate g = ready();
            require(!g.tick("one", 61_002), "unattended call expires");
        });
        check("media-prepare-timeout", () -> {
            PlaybackGate g = ready();
            g.beginPrepare("one", 1_003);
            require(!g.preparedMuted("one", 21_003), "late async preparation");
        });
        check("muted-route-verification-two-second-bound", () -> {
            PlaybackGate g = muted();
            require(!g.confirmPlayerRoute("one", true, 4_000), "late verification");
            require(g.state() == PlaybackGate.State.STOPPED, "no delayed unmute");
        });
        check("ten-second-limit-does-not-slide-on-route-callbacks", () -> {
            PlaybackGate g = playing();
            require(g.confirmPlayerRoute("one", true, 11_999), "before cap");
            require(g.deadlineMs() == 12_000, "unchanged original cap");
            require(!g.tick("one", 12_000), "cap includes muted period");
        });
        check("explicit-stop-idempotent-and-late-prepare-denied", () -> {
            PlaybackGate g = ready();
            g.beginPrepare("one", 1_003);
            require(g.stop("one", "user-stop"), "stop");
            require(!g.stop("one", "second"), "idempotent");
            require(!g.preparedMuted("one", 1_004), "late callback denied");
            require(g.stopReason().equals("user-stop"), "first reason retained");
        });
        check("stale-session-events-cannot-alter-new-call", () -> {
            PlaybackGate g = playing();
            g.stop("one", "finished");
            require(g.start("two", 5_000), "new call");
            long deadline = g.deadlineMs();
            require(!g.answer("one", 5_001), "stale answer");
            require(!g.stop("one", "late-error"), "stale error");
            require(!g.confirmPlayerRoute("one", false, 5_002), "stale media loss");
            require(!g.tick("one", 100_000), "stale timeout");
            require(g.state() == PlaybackGate.State.WAITING_FOR_ANSWER && g.deadlineMs() == deadline,
                    "new call unchanged");
        });
        check("stopped-token-cannot-be-reused", () -> {
            PlaybackGate g = waiting();
            g.stop("one", "stop");
            require(!g.start("one", 2_000), "same token cannot restart");
            require(g.start("two", 2_001), "fresh token");
        });
        check("second-play-button-cannot-start-another-player", () -> {
            PlaybackGate g = ready();
            require(g.beginPrepare("one", 1_003), "first button");
            require(!g.beginPrepare("one", 1_004), "duplicate button");
        });
        check("hold-or-error-stop-cannot-be-undone-by-route-update", () -> {
            PlaybackGate g = playing();
            require(g.stop("one", "hold"), "hold");
            require(!g.confirmCallRoute("one", true, 2_002), "late endpoint update");
            require(!g.confirmPlayerRoute("one", true, 2_003), "late player update");
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
