package org.garmin.hfpprototype;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Handler;
import android.os.SystemClock;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** One process-wide proxy request; profile snapshots/close run on one reusable background worker. */
final class HfpPreflight {
    interface Listener {
        void finished(HfpPreflight request, boolean admitted, String reason);
    }
    private static final HfpPreflightLease LEASE = new HfpPreflightLease();
    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(action -> {
        Thread thread = new Thread(action, "Garmin-HFP-preflight");
        thread.setDaemon(true);
        return thread;
    });

    static boolean isBusy() { return LEASE.busy(); }
    static HfpPreflight reserve(Context app, Handler main, BluetoothAdapter adapter,
                                BluetoothDevice selected, String selectedIdentity,
                                String sessionId, Listener listener) {
        HfpPreflightLease.Ticket ticket = LEASE.tryAcquire(sessionId, selectedIdentity,
                SystemClock.elapsedRealtime());
        return ticket == null ? null : new HfpPreflight(app, main, adapter, selected,
                selectedIdentity, sessionId, listener, ticket);
    }

    private final Context app;
    private final Handler main;
    private final BluetoothAdapter adapter;
    private final BluetoothDevice selected;
    private final String selectedIdentity;
    private final String sessionId;
    private final Listener listener;
    private final HfpPreflightLease.Ticket ticket;
    private final AtomicReference<BluetoothProfile> firstProxy = new AtomicReference<>();
    private final AtomicBoolean closing = new AtomicBoolean();
    private boolean started; // Main-looper only.
    private boolean reported; // Main-looper only.
    private long admittedSnapshotAt = -1; // Main-looper; rechecked immediately before Telecom admission.

    private HfpPreflight(Context app, Handler main, BluetoothAdapter adapter,
                         BluetoothDevice selected, String selectedIdentity,
                         String sessionId, Listener listener, HfpPreflightLease.Ticket ticket) {
        this.app = app;
        this.main = main;
        this.adapter = adapter;
        this.selected = selected;
        this.selectedIdentity = selectedIdentity;
        this.sessionId = sessionId;
        this.listener = listener;
        this.ticket = ticket;
        main.postDelayed(timeout, HfpPreflightLease.TIMEOUT_MS);
    }

    void start() { // Called once, after phoneCall foreground has started.
        if (started || reported) return;
        started = true;
        WORKER.execute(() -> {
            boolean issued = false;
            try {
                if (!ticket.allowsObservation(SystemClock.elapsedRealtime())) {
                    completeWithoutProxy("HFP-preflight-canceled-before-request");
                    return;
                }
                requirePermission();
                issued = true;
                if (!adapter.getProfileProxy(app, serviceListener, BluetoothProfile.HEADSET)) {
                    completeWithoutProxy("HFP-profile-request-refused");
                }
                // A true return is only a pending service request, never selected-device admission.
            } catch (RuntimeException error) {
                ticket.cancel();
                // Once issued, an exception does not prove there is no pending platform resource.
                if (!issued) LEASE.releaseAfterCleanup(ticket);
                report(false, "HFP-profile-request-error");
            }
        });
    }

    private void requirePermission() {
        if (Build.VERSION.SDK_INT >= 31
                && app.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) throw new SecurityException();
    }

    private final BluetoothProfile.ServiceListener serviceListener = new BluetoothProfile.ServiceListener() {
        @Override public void onServiceConnected(int profile, BluetoothProfile proxy) {
            // Public getProfileProxy specifies main-looper callbacks; never issue snapshot Binder queries here.
            if (proxy == null) {
                ticket.cancel();
                report(false, "HFP-profile-missing-proxy");
                return; // No proxy to close: retain the lease rather than pretending cleanup happened.
            }
            if (!firstProxy.compareAndSet(null, proxy)) {
                if (firstProxy.get() == proxy) return; // Same proxy already owns an observation/close job.
                // An unexpected distinct proxy is not covered by the first cleanup result. Revoke
                // admission and permanently refuse retries, even if its queued close later succeeds.
                ticket.cancel();
                LEASE.cleanupFailed();
                WORKER.execute(() -> closeLateProxy(profile, proxy));
                report(false, "HFP-unexpected-additional-proxy");
                return;
            }
            WORKER.execute(() -> observeAndClose(profile, proxy));
        }
        @Override public void onServiceDisconnected(int profile) {
            if (profile != BluetoothProfile.HEADSET || closing.get()) return;
            ticket.cancel();
            report(false, "HFP-profile-service-disconnected");
            // A disconnect callback provides no closeable proxy and is not cleanup evidence.
        }
    };

    private void observeAndClose(int profile, BluetoothProfile proxy) {
        boolean permission = false;
        boolean bonded = false;
        boolean connected = false;
        int selectedMatches = 0;
        long observedAt = 0;
        String reason = "HFP-selected-device-not-connected";
        try {
            if (ticket.allowsObservation(SystemClock.elapsedRealtime())
                    && profile == BluetoothProfile.HEADSET && proxy instanceof BluetoothHeadset) {
                requirePermission();
                BluetoothHeadset headset = (BluetoothHeadset) proxy;
                observedAt = SystemClock.elapsedRealtime(); // Old first-query data is not freshened by a slow close.
                connected = headset.getConnectionState(selected) == BluetoothProfile.STATE_CONNECTED;
                List<BluetoothDevice> devices = headset.getConnectedDevices();
                if (devices != null) {
                    for (BluetoothDevice device : devices) {
                        if (selected.equals(device)) selectedMatches++;
                    }
                }
                bonded = selected.getBondState() == BluetoothDevice.BOND_BONDED
                        && selectedIdentity.equals(selected.getAddress());
                requirePermission();
                permission = true;
            }
        } catch (RuntimeException error) {
            ticket.cancel();
            reason = "HFP-snapshot-permission-or-service-error";
        }
        boolean cleaned = false;
        try {
            closing.set(true); // Ignore service-disconnected notification from our deliberate close only.
            adapter.closeProfileProxy(profile, proxy);
            cleaned = true;
        } catch (RuntimeException error) {
            ticket.cancel();
            LEASE.cleanupFailed();
            reason = "HFP-proxy-cleanup-incomplete";
        }
        final boolean wasCleaned = cleaned;
        final boolean hasPermission = permission;
        final boolean isBonded = bonded;
        final boolean isConnected = connected;
        final int matches = selectedMatches;
        final long snapshotAt = observedAt;
        final String failureReason = reason;
        main.post(() -> {
            boolean admitted = wasCleaned && LEASE.admit(ticket, sessionId, selectedIdentity,
                    hasPermission, isBonded, isConnected, matches, snapshotAt,
                    SystemClock.elapsedRealtime());
            if (admitted) admittedSnapshotAt = snapshotAt;
            if (wasCleaned) LEASE.releaseAfterCleanup(ticket);
            reportOnMain(admitted, admitted ? "HFP-selected-connected-snapshot" : failureReason);
        });
    }

    private void closeLateProxy(int profile, BluetoothProfile proxy) {
        try { adapter.closeProfileProxy(profile, proxy); }
        catch (RuntimeException error) {
            // No admission/retry is authorized by duplicate or late callbacks.
            ticket.cancel();
            LEASE.cleanupFailed();
            report(false, "HFP-late-proxy-cleanup-incomplete");
        }
    }

    private void completeWithoutProxy(String reason) {
        ticket.cancel();
        LEASE.releaseAfterCleanup(ticket);
        report(false, reason);
    }

    private void report(boolean admitted, String reason) {
        main.post(() -> reportOnMain(admitted, reason));
    }
    private void reportOnMain(boolean admitted, String reason) {
        if (reported) return;
        reported = true;
        main.removeCallbacks(timeout);
        listener.finished(this, admitted, reason);
    }

    private final Runnable timeout = new Runnable() {
        @Override public void run() {
            ticket.cancel();
            // Pending request, blocked query, or failed close stays owned until real cleanup.
            if (!started) LEASE.releaseAfterCleanup(ticket);
            reportOnMain(false, "HFP-preflight-timeout");
        }
    };

    void cancel() { // Main-looper: no join, profile query, close, or platform cancellation call.
        ticket.cancel();
        main.removeCallbacks(timeout);
        reported = true;
        if (!started) LEASE.releaseAfterCleanup(ticket);
    }

    boolean hasFreshAdmission(long nowMs) {
        return !LEASE.isCleanupFaulted() && admittedSnapshotAt >= 0 && nowMs >= admittedSnapshotAt
                && nowMs - admittedSnapshotAt <= HfpPreflightLease.SNAPSHOT_MAX_AGE_MS
                && nowMs < ticket.deadlineMs();
    }
}
