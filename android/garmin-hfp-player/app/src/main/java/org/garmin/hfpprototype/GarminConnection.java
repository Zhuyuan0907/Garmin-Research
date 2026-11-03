package org.garmin.hfpprototype;

import android.bluetooth.BluetoothDevice;
import android.net.Uri;
import android.os.Build;
import android.telecom.CallAudioState;
import android.telecom.Connection;
import android.telecom.TelecomManager;

/** API 28-33 implementation; API 34 endpoint types are isolated in the subclass. */
class GarminConnection extends Connection {
    final TestSession session;
    final String token;
    private boolean legacyRequestSent;

    GarminConnection(TestSession session, String token) {
        this.session = session;
        this.token = token;
        setConnectionProperties(PROPERTY_SELF_MANAGED);
        setConnectionCapabilities(0);
        setAudioModeIsVoip(true); // Telecom owns communication mode and routing.
        setAddress(Uri.parse(TestSession.LOCAL_CALL_ADDRESS), TelecomManager.PRESENTATION_ALLOWED);
        setCallerDisplayName("Garmin 本機音檔試驗", TelecomManager.PRESENTATION_ALLOWED);
        setInitializing();
        setRinging(); // Never setActive before returning the Connection to Telecom.
    }

    @Override public void onAnswer() { session.answerFromTelecom(this); }
    @Override public void onAnswer(int videoState) { session.answerFromTelecom(this); }
    @Override public void onDisconnect() { session.endFromConnection(this, "telecom-disconnect"); }
    @Override public void onAbort() { session.endFromConnection(this, "telecom-abort"); }
    @Override public void onReject() { session.endFromConnection(this, "telecom-reject"); }
    @Override public void onReject(String ignored) { onReject(); }
    @Override public void onReject(int ignored) { onReject(); }
    @Override public void onHold() { session.endFromConnection(this, "telecom-hold"); }
    @Override public void onUnhold() { session.endFromConnection(this, "unexpected-unhold"); }
    @Override public void onShowIncomingCallUi() { session.showIncomingUi(this); }
    @Override public void onSilence() { session.logCurrent(this, "ringer-silence (app has no ringtone)"); }

    @Override public void onStateChanged(int state) {
        // Constructor callbacks occur before TestSession stores the returned Connection.
        session.logCurrent(this, "Call state=" + Connection.stateToString(state));
        if (state == STATE_HOLDING || state == STATE_DISCONNECTED) {
            session.endFromConnection(this, "call-state-" + state);
        }
    }

    @Override public void onCallAudioStateChanged(CallAudioState state) {
        if (Build.VERSION.SDK_INT < 34) session.routeChanged(this);
    }

    @SuppressWarnings("deprecation")
    void requestSelectedRoute() {
        if (Build.VERSION.SDK_INT >= 34 || legacyRequestSent || getState() != STATE_ACTIVE) return;
        CallAudioState audio = getCallAudioState();
        if (audio == null) return;
        BluetoothDevice selected = session.selectedDevice(token);
        if (selected == null) return;
        for (BluetoothDevice available : audio.getSupportedBluetoothDevices()) {
            if (selected.equals(available)) {
                legacyRequestSent = true;
                EventLog.add("request Bluetooth route: selected paired device");
                requestBluetoothAudio(selected);
                // A request is not confirmation; isSelectedRoute checks actual state.
                return;
            }
        }
    }

    @SuppressWarnings("deprecation")
    boolean isSelectedRoute() {
        if (getState() != STATE_ACTIVE) return false;
        CallAudioState audio = getCallAudioState();
        BluetoothDevice selected = session.selectedDevice(token);
        return audio != null && audio.getRoute() == CallAudioState.ROUTE_BLUETOOTH
                && selected != null && selected.equals(audio.getActiveBluetoothDevice());
    }
}
