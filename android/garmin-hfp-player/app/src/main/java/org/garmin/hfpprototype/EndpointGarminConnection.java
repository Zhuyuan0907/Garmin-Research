package org.garmin.hfpprototype;

import android.annotation.TargetApi;
import android.os.OutcomeReceiver;
import android.telecom.CallEndpoint;
import android.telecom.CallEndpointException;
import java.util.ArrayList;
import java.util.List;

/** Loaded only on API 34+. Uses only framework-provided endpoint instances. */
@TargetApi(34)
final class EndpointGarminConnection extends GarminConnection {
    private List<CallEndpoint> available = new ArrayList<>();
    private CallEndpoint selectedEndpoint;
    private CallEndpoint observedCurrent;
    private boolean requestSent;

    EndpointGarminConnection(TestSession session, String token) { super(session, token); }

    @Override public void onAvailableCallEndpointsChanged(List<CallEndpoint> endpoints) {
        available = new ArrayList<>(endpoints);
        session.logCurrent(this, "available endpoint list changed count=" + available.size());
        session.routeChanged(this);
    }

    @Override public void onCallEndpointChanged(CallEndpoint endpoint) {
        observedCurrent = endpoint;
        // Never log endpoint.toString(), identifier, Bluetooth address or device name.
        session.logCurrent(this, "Call endpoint callback type=" + endpoint.getEndpointType());
        session.routeChanged(this);
    }

    @Override public void onMuteStateChanged(boolean muted) {
        session.logCurrent(this, "Call mute=" + muted + " (no microphone capture)");
    }

    @Override void requestSelectedRoute() {
        if (getState() != STATE_ACTIVE || !session.isConnectionCurrent(this)) return;
        String wantedName = session.selectedUniqueName(token);
        if (wantedName == null) {
            session.endFromConnection(this, "ambiguous-paired-device-name");
            return;
        }
        CallEndpoint candidate = null;
        int matches = 0;
        for (CallEndpoint endpoint : available) {
            if (endpoint.getEndpointType() == CallEndpoint.TYPE_BLUETOOTH
                    && wantedName.contentEquals(endpoint.getEndpointName())) {
                candidate = endpoint;
                matches++;
            }
        }
        if (matches > 1) {
            session.endFromConnection(this, "ambiguous-Bluetooth-endpoint-name");
            return;
        }
        if (matches == 0) {
            if (selectedEndpoint != null) session.endFromConnection(this, "selected-endpoint-unavailable");
            return;
        }
        if (selectedEndpoint != null
                && !selectedEndpoint.getIdentifier().equals(candidate.getIdentifier())) {
            session.endFromConnection(this, "selected-endpoint-replaced");
            return;
        }
        selectedEndpoint = candidate;
        if (requestSent) return;
        requestSent = true;
        EventLog.add("request CallEndpoint: unique selected Bluetooth match");
        requestCallEndpointChange(selectedEndpoint, session.mainExecutor(),
                new OutcomeReceiver<Void, CallEndpointException>() {
                    @Override public void onResult(Void ignored) {
                        session.logCurrent(EndpointGarminConnection.this,
                                "endpoint request accepted; actual callback still required");
                        session.routeChanged(EndpointGarminConnection.this);
                    }
                    @Override public void onError(CallEndpointException error) {
                        if (!session.isConnectionCurrent(EndpointGarminConnection.this)) return;
                        EventLog.add("endpoint request error code=" + error.getCode());
                        session.endFromConnection(EndpointGarminConnection.this, "endpoint-request-error");
                    }
                });
    }

    @Override boolean isSelectedRoute() {
        if (getState() != STATE_ACTIVE || selectedEndpoint == null
                || session.selectedUniqueName(token) == null) return false;
        CallEndpoint current = getCurrentCallEndpoint();
        if (current == null || current.getEndpointType() != CallEndpoint.TYPE_BLUETOOTH
                || observedCurrent == null
                || observedCurrent.getEndpointType() != CallEndpoint.TYPE_BLUETOOTH
                || !selectedEndpoint.getIdentifier().equals(observedCurrent.getIdentifier())
                || !selectedEndpoint.getIdentifier().equals(current.getIdentifier())) return false;
        // Both the selected endpoint and its identifier must remain present and unique.
        int names = 0;
        boolean present = false;
        String name = session.selectedUniqueName(token);
        for (CallEndpoint endpoint : available) {
            if (endpoint.getEndpointType() == CallEndpoint.TYPE_BLUETOOTH
                    && name.contentEquals(endpoint.getEndpointName())) {
                names++;
                present |= endpoint.getIdentifier().equals(selectedEndpoint.getIdentifier());
            }
        }
        return present && names == 1;
    }
}
