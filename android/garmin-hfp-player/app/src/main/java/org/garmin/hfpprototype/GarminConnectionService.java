package org.garmin.hfpprototype;

import android.telecom.Connection;
import android.telecom.ConnectionRequest;
import android.telecom.ConnectionService;
import android.telecom.DisconnectCause;
import android.telecom.PhoneAccountHandle;

public final class GarminConnectionService extends ConnectionService {
    private GarminConnection ownedConnection;
    @Override public Connection onCreateIncomingConnection(PhoneAccountHandle manager,
                                                           ConnectionRequest request) {
        TestSession session = TestSession.get(this);
        GarminConnection connection = session.createIncoming(request);
        if (connection != null) ownedConnection = connection;
        return connection != null ? connection
                : Connection.createFailedConnection(new DisconnectCause(DisconnectCause.ERROR));
    }

    @Override public void onCreateIncomingConnectionFailed(PhoneAccountHandle manager,
                                                          ConnectionRequest request) {
        TestSession.get(this).incomingFailed(request);
    }

    @Override public Connection onCreateOutgoingConnection(PhoneAccountHandle manager,
                                                           ConnectionRequest request) {
        return Connection.createFailedConnection(new DisconnectCause(DisconnectCause.RESTRICTED));
    }

    @Override public void onConnectionServiceFocusLost() {
        TestSession.get(this).endFromConnection(ownedConnection, "Telecom-focus-lost");
        connectionServiceFocusReleased();
    }

    @Override public void onConnectionServiceFocusGained() {
        EventLog.add("Telecom focus gained");
    }

    @Override public void onDestroy() {
        TestSession.get(this).endFromConnection(ownedConnection, "ConnectionService-destroyed");
        super.onDestroy();
    }
}
