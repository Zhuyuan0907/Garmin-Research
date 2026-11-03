package org.garmin.hfpprototype;

import android.os.Build;
import android.os.SystemClock;
import android.util.Log;
import java.util.ArrayDeque;

/** Bounded local diagnostics. Never pass device/address/URI/exception message objects here. */
final class EventLog {
    private static final int LIMIT = 160;
    private static final ArrayDeque<String> EVENTS = new ArrayDeque<>();
    private static final long START = SystemClock.elapsedRealtime();
    static { add("Android API=" + Build.VERSION.SDK_INT); }

    static synchronized void add(String safeEvent) {
        String line = (SystemClock.elapsedRealtime() - START) + "ms " + safeEvent;
        if (EVENTS.size() == LIMIT) EVENTS.removeFirst();
        EVENTS.addLast(line);
        Log.i("GarminHfpPrototype", line);
    }

    static void error(String operation, Throwable error) {
        add(operation + " error=" + error.getClass().getSimpleName());
    }

    static synchronized String snapshot() {
        StringBuilder out = new StringBuilder();
        for (String line : EVENTS) out.append(line).append('\n');
        return out.toString();
    }
}
