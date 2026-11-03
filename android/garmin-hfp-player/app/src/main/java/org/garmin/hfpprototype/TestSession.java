package org.garmin.hfpprototype;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.UriPermission;
import android.content.pm.PackageManager;
import android.media.AudioAttributes;
import android.media.AudioDeviceCallback;
import android.media.AudioDeviceInfo;
import android.media.AudioFocusRequest;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.telecom.Connection;
import android.telecom.ConnectionRequest;
import android.telecom.DisconnectCause;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import java.util.UUID;
import java.util.concurrent.Executor;

/** Main-looper session/Telecom policy; AsyncPlayer alone owns MediaPlayer and provider I/O. */
final class TestSession {
    static final String EXTRA_TOKEN = "org.garmin.hfpprototype.SESSION";
    // An opaque self-managed handle, never a carrier dial request. Digits stay consistent in HFP.
    static final String LOCAL_CALL_ADDRESS = "garminmusic:0000";
    private static TestSession instance;
    static synchronized TestSession get(Context context) {
        if (instance == null) instance = new TestSession(context.getApplicationContext());
        return instance;
    }

    private final Context app;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final PlaybackGate gate = new PlaybackGate();
    private final AudioManager audioManager;
    private final TelecomManager telecom;
    private final PhoneAccountHandle account;
    private Uri source;
    private BluetoothDevice selected;
    private String selectedAddress; // Private runtime identity; never logged or persisted.
    private String selectedName;
    private String token;
    private GarminConnection connection;
    private CallForegroundService foreground;
    private AsyncPlayer player;
    private AsyncPlayer releasingPlayer;
    private AudioFocusRequest focus;
    private AudioDeviceCallback deviceObserver;
    private boolean deviceObserverRegistered;
    private boolean incomingUiAllowed;
    private boolean ending;
    private boolean audible;
    private HfpPreflight hfpPreflight;
    private boolean incomingRequested;

    private TestSession(Context app) {
        this.app = app;
        audioManager = app.getSystemService(AudioManager.class);
        telecom = app.getSystemService(TelecomManager.class);
        account = new PhoneAccountHandle(new ComponentName(app, GarminConnectionService.class),
                "garmin-local-audio");
    }

    Executor mainExecutor() { return command -> main.post(command); }
    private long now() { return SystemClock.elapsedRealtime(); }
    private void run(Runnable action) {
        if (Looper.myLooper() == Looper.getMainLooper()) action.run(); else main.post(action);
    }
    boolean isLive() { return gate.state() != PlaybackGate.State.IDLE
            && gate.state() != PlaybackGate.State.STOPPED; }
    String token() { return token; }
    String status() {
        return "Android API " + Build.VERSION.SDK_INT + " · " + gate.state()
                + (hfpPreflight != null ? " · 正在確認所選裝置的 HFP 連線" : "")
                + (gate.state() == PlaybackGate.State.STOPPED ? " · " + gate.stopReason() : "")
                + (!isLive() && AsyncPlayer.isBusy() ? " · 背景音檔尚未回收，新試驗暫時拒絕" : "")
                + (!isLive() && HfpPreflight.isBusy() ? " · HFP 檢查尚未回收，新試驗暫時拒絕" : "");
    }
    boolean canStart() { return !isLive() && !AsyncPlayer.isBusy() && !HfpPreflight.isBusy(); }
    boolean canAnswer() { return isLive() && incomingUiAllowed && connection != null
            && connection.getState() == Connection.STATE_RINGING; }
    boolean canPlay() { return gate.state() == PlaybackGate.State.READY; }

    /** Only called by the visible Activity's explicit 'local incoming test' button. */
    void begin(Uri localSource, BluetoothDevice chosen) {
        if (isLive()) { EventLog.add("start refused: a session already exists"); return; }
        if (AsyncPlayer.isBusy()) {
            EventLog.add("背景載入／播放器尚未回收：拒絕新試驗；供應者可能尚未返回");
            return;
        }
        if (HfpPreflight.isBusy()) {
            EventLog.add("HFP profile 檢查尚未回收：拒絕新試驗，不新增 proxy request");
            return;
        }
        try {
            if (telecom == null || audioManager == null) throw new IllegalStateException();
            requireBluetoothPermission();
            requirePersistedSource(localSource);
            if (chosen == null || chosen.getBondState() != BluetoothDevice.BOND_BONDED) {
                throw new IllegalArgumentException();
            }
            BluetoothManager manager = app.getSystemService(BluetoothManager.class);
            BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
            if (adapter == null || !adapter.isEnabled()
                    || !adapter.getBondedDevices().contains(chosen)) throw new IllegalStateException();
            selected = chosen;
            selectedName = chosen.getName();
            selectedAddress = chosen.getAddress();
            if (Build.VERSION.SDK_INT >= 34 && selectedUniqueNameUnchecked() == null) {
                EventLog.add("start refused: selected bonded name missing or ambiguous");
                clearSourceAndDevice();
                return;
            }
            Bundle accountExtras = new Bundle();
            if (Build.VERSION.SDK_INT >= 31) {
                accountExtras.putBoolean(PhoneAccount.EXTRA_ADD_SELF_MANAGED_CALLS_TO_INCALLSERVICE, true);
            }
            PhoneAccount phoneAccount = PhoneAccount.builder(account, "Garmin 本機音檔試驗")
                    .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)
                    .addSupportedUriScheme("garminmusic")
                    .setExtras(accountExtras)
                    .build();
            telecom.registerPhoneAccount(phoneAccount);
            PhoneAccount registered = telecom.getPhoneAccount(account);
            if (registered == null || !registered.hasCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)) {
                throw new SecurityException();
            }
            if (!telecom.isIncomingCallPermitted(account)) {
                EventLog.add("start refused: Telecom does not permit this incoming call");
                clearSourceAndDevice();
                return;
            }
            source = localSource;
            token = UUID.randomUUID().toString();
            gate.start(token, now());
            final String preflightToken = token;
            hfpPreflight = HfpPreflight.reserve(app, main, adapter, selected, selectedAddress,
                    preflightToken, (request, admitted, reason) -> {
                        if (request != hfpPreflight || !gate.isCurrent(preflightToken) || !isLive()) return;
                        hfpPreflight = null;
                        if (!admitted) { finish(reason, DisconnectCause.ERROR); return; }
                        try {
                            requireBluetoothPermission();
                            if (foreground == null || selected == null
                                    || selected.getBondState() != BluetoothDevice.BOND_BONDED
                                    || (Build.VERSION.SDK_INT >= 34 && selectedUniqueNameUnchecked() == null)
                                    || !gate.tick(preflightToken, now())) {
                                finish("HFP-before-call-session-or-identity-lost", DisconnectCause.ERROR);
                                return;
                            }
                            addVerifiedIncomingCall(preflightToken, request);
                        } catch (RuntimeException error) {
                            EventLog.error("HFP before-call admission", error);
                            finish("HFP-before-call-error", DisconnectCause.ERROR);
                        }
                    });
            if (hfpPreflight == null) {
                finish("HFP-preflight-busy", DisconnectCause.ERROR);
                return;
            }
            incomingRequested = false;
            incomingUiAllowed = false;
            audible = false;
            EventLog.add("session started: local document / selected paired device");
            main.post(watchdog);
            Intent start = new Intent(app, CallForegroundService.class)
                    .setAction(CallForegroundService.ACTION_START).putExtra(EXTRA_TOKEN, token);
            app.startForegroundService(start);
        } catch (RuntimeException error) {
            EventLog.error("visible start", error);
            if (isLive()) finish("foreground-or-Telecom-start-error", DisconnectCause.ERROR);
            else clearSourceAndDevice();
        }
    }

    private void requireBluetoothPermission() {
        if (Build.VERSION.SDK_INT >= 31
                && app.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) throw new SecurityException();
    }

    private void requirePersistedSource(Uri uri) {
        if (uri == null || !"content".equals(uri.getScheme())) throw new IllegalArgumentException();
        boolean permitted = false;
        for (UriPermission permission : app.getContentResolver().getPersistedUriPermissions()) {
            permitted |= permission.isReadPermission() && uri.equals(permission.getUri());
        }
        if (!permitted) throw new SecurityException();
        // Grant check only: do not synchronously open a provider as repeated preflight I/O.
        // Actual MediaPlayer data-source failure is handled by the Play cleanup path.
    }

    void foregroundReady(CallForegroundService service, String suppliedToken) {
        if (!gate.isCurrent(suppliedToken) || !isLive()) { service.endForeground(); return; }
        foreground = service;
        try {
            final String observerToken = suppliedToken;
            deviceObserver = new AudioDeviceCallback() {
                @Override public void onAudioDevicesRemoved(AudioDeviceInfo[] removed) {
                    if (!gate.isCurrent(observerToken) || !isLive()
                            || gate.state() == PlaybackGate.State.WAITING_FOR_ANSWER) return;
                    for (AudioDeviceInfo info : removed) {
                        if (isExactSco(info)) {
                            finish("selected-SCO-output-removed", DisconnectCause.ERROR);
                            return;
                        }
                    }
                }
            };
            audioManager.registerAudioDeviceCallback(deviceObserver, main);
            deviceObserverRegistered = true;
            if (hfpPreflight == null || incomingRequested) {
                finish("HFP-preflight-absent-before-call", DisconnectCause.ERROR);
                return;
            }
            EventLog.add("checking selected-device HEADSET profile before local incoming call");
            hfpPreflight.start();
        } catch (RuntimeException error) {
            EventLog.error("local incoming call", error);
            finish("incoming-call-error", DisconnectCause.ERROR);
        }
    }

    private void addVerifiedIncomingCall(String suppliedToken, HfpPreflight request) {
        if (!gate.isCurrent(suppliedToken) || !isLive() || foreground == null || incomingRequested) return;
        if (!request.hasFreshAdmission(now())) {
            finish("HFP-before-call-snapshot-expired", DisconnectCause.ERROR);
            return;
        }
        Bundle extras = new Bundle();
        extras.putString(EXTRA_TOKEN, suppliedToken);
        extras.putParcelable(TelecomManager.EXTRA_INCOMING_CALL_ADDRESS, Uri.parse(LOCAL_CALL_ADDRESS));
        incomingRequested = true;
        EventLog.add("selected HFP connected snapshot confirmed; addNewIncomingCall (not proof of sound)");
        telecom.addNewIncomingCall(account, extras);
    }

    GarminConnection createIncoming(ConnectionRequest request) {
        Bundle extras = request.getExtras();
        String supplied = extras == null ? null : extras.getString(EXTRA_TOKEN);
        if (!gate.isCurrent(supplied) || !isLive() || !incomingRequested || connection != null || foreground == null
                || !account.equals(request.getAccountHandle())
                || gate.state() != PlaybackGate.State.WAITING_FOR_ANSWER) {
            EventLog.add("incoming connection rejected: absent/stale local session");
            return null;
        }
        connection = Build.VERSION.SDK_INT >= 34
                ? new EndpointGarminConnection(this, token) : new GarminConnection(this, token);
        EventLog.add("Call state=RINGING; waiting for user or Garmin answer");
        return connection;
    }

    void incomingFailed(ConnectionRequest request) {
        Bundle extras = request.getExtras();
        if (extras != null && gate.isCurrent(extras.getString(EXTRA_TOKEN))) {
            finish("Telecom-incoming-denied", DisconnectCause.REJECTED);
        }
    }

    boolean isConnectionCurrent(GarminConnection supplied) {
        return supplied != null && supplied == connection && gate.isCurrent(supplied.token) && isLive();
    }

    void answerFromTelecom(GarminConnection supplied) {
        run(() -> {
            if (!isConnectionCurrent(supplied)) return;
            if (!gate.answer(supplied.token, now())) { checkStopped(); return; }
            incomingUiAllowed = false;
            try {
                supplied.setActive();
                EventLog.add("answered; playback still requires visible Play button");
                if (foreground != null) foreground.refreshNotification();
                routeChanged(supplied);
            } catch (RuntimeException error) {
                EventLog.error("Telecom answer", error);
                finish("Telecom-answer-error", DisconnectCause.ERROR);
            }
        });
    }

    void answerFromVisibleUi() {
        if (canAnswer()) connection.onAnswer();
        else EventLog.add("answer refused: incoming UI not authorized or no ringing call");
    }

    void answerFromNotification(String suppliedToken) {
        if (gate.isCurrent(suppliedToken)) answerFromVisibleUi();
    }

    void showIncomingUi(GarminConnection supplied) {
        run(() -> {
            if (!isConnectionCurrent(supplied)) return;
            incomingUiAllowed = true;
            EventLog.add("onShowIncomingCallUi: visible Activity + silent incoming CallStyle");
            if (foreground != null) foreground.refreshNotification();
        });
    }

    boolean notificationIsIncoming() { return canAnswer(); }

    void logCurrent(GarminConnection supplied, String event) {
        run(() -> { if (isConnectionCurrent(supplied)) EventLog.add(event); });
    }

    void endFromConnection(GarminConnection supplied, String reason) {
        run(() -> { if (isConnectionCurrent(supplied)) finish(reason, DisconnectCause.LOCAL); });
    }

    BluetoothDevice selectedDevice(String suppliedToken) {
        return gate.isCurrent(suppliedToken) && isLive() ? selected : null;
    }

    String selectedUniqueName(String suppliedToken) {
        if (!gate.isCurrent(suppliedToken) || !isLive()) return null;
        try { requireBluetoothPermission(); return selectedUniqueNameUnchecked(); }
        catch (RuntimeException error) { return null; }
    }

    private String selectedUniqueNameUnchecked() {
        if (selected == null || selectedName == null || selectedName.trim().isEmpty()
                || selected.getBondState() != BluetoothDevice.BOND_BONDED
                || !selectedName.equals(selected.getName())) return null;
        BluetoothManager manager = app.getSystemService(BluetoothManager.class);
        BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
        if (adapter == null) return null;
        int matches = 0;
        for (BluetoothDevice device : adapter.getBondedDevices()) {
            if (selectedName.equals(device.getName())) matches++;
        }
        return matches == 1 ? selectedName : null;
    }

    void routeChanged(GarminConnection supplied) {
        run(() -> {
            if (!isConnectionCurrent(supplied)
                    || gate.state() == PlaybackGate.State.WAITING_FOR_ANSWER) return;
            try {
                supplied.requestSelectedRoute();
                if (!isConnectionCurrent(supplied)) return;
                PlaybackGate.State before = gate.state();
                boolean matches = supplied.isSelectedRoute();
                gate.confirmCallRoute(supplied.token, matches, now());
                if (before == PlaybackGate.State.WAITING_FOR_ROUTE && gate.state() == PlaybackGate.State.READY) {
                    EventLog.add("actual Call route confirmed: selected Garmin; Play enabled");
                }
                checkStopped();
                inspectPlayerRoute();
            } catch (RuntimeException error) {
                EventLog.error("Call route", error);
                finish("call-route-error", DisconnectCause.ERROR);
            }
        });
    }

    /** Only the Activity's explicit Play button calls this; answer/route callbacks never autoplay. */
    void playFromVisibleUi() {
        String playToken = token;
        if (!isLive() || connection == null) { EventLog.add("Play refused: no active call"); return; }
        try {
            requireBluetoothPermission();
            routeChanged(connection);
            if (!gate.beginPrepare(playToken, now())) {
                EventLog.add("Play refused: waiting for answer/selected route, or already started");
                checkStopped();
                return;
            }
            requirePersistedSource(source);
            AudioDeviceInfo sco = findExactScoOutput();
            if (sco == null) {
                EventLog.add("Play refused: no unique SCO output with selected Bluetooth address");
                finish("no-exact-SCO-output", DisconnectCause.ERROR);
                return;
            }
            AudioAttributes attributes = new AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC).build();
            focus = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
                    .setAudioAttributes(attributes).setAcceptsDelayedFocusGain(false)
                    .setWillPauseWhenDucked(true)
                    .setOnAudioFocusChangeListener(change -> {
                        if (gate.isCurrent(playToken) && isLive() && change != AudioManager.AUDIOFOCUS_GAIN) {
                            finish("audio-focus-loss", DisconnectCause.LOCAL);
                        }
                    }, main).build();
            if (audioManager.requestAudioFocus(focus) != AudioManager.AUDIOFOCUS_REQUEST_GRANTED) {
                finish("audio-focus-denied", DisconnectCause.ERROR);
                return;
            }
            if (!gate.isCurrent(playToken) || !isLive()) return;
            AsyncPlayer candidate = AsyncPlayer.create(playToken, gate.deadlineMs(), main, playerListener);
            if (candidate == null) {
                EventLog.add("背景載入尚未回收：拒絕播放，不新增載入工作");
                finish("media-loader-busy", DisconnectCause.ERROR);
                return;
            }
            player = candidate;
            candidate.load(app, source, attributes, sco, selectedAddress);
            EventLog.add("player preparing off main: local descriptor / VOICE_COMMUNICATION / muted start only");
        } catch (RuntimeException error) {
            EventLog.error("Play", error);
            finish("media-prepare-error", DisconnectCause.ERROR);
        }
    }

    private AudioDeviceInfo findExactScoOutput() {
        AudioDeviceInfo match = null;
        int outputs = 0;
        int emptyAddresses = 0;
        int matches = 0;
        for (AudioDeviceInfo info : audioManager.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
            if (info.isSink() && info.getType() == AudioDeviceInfo.TYPE_BLUETOOTH_SCO) {
                outputs++;
                if (info.getAddress().isEmpty()) emptyAddresses++;
            }
            if (isExactSco(info)) {
                matches++;
                match = info;
            }
        }
        // Counts only: never include a device address/name, including a nonempty unknown address.
        EventLog.add("SCO preflight: outputs=" + outputs + " empty-address=" + emptyAddresses
                + " selected-matches=" + matches);
        return matches == 1 ? match : null;
    }

    private boolean isExactSco(AudioDeviceInfo info) {
        return info != null && info.isSink() && info.getType() == AudioDeviceInfo.TYPE_BLUETOOTH_SCO
                && selectedAddress != null && !selectedAddress.isEmpty()
                && selectedAddress.equalsIgnoreCase(info.getAddress());
    }

    private void inspectPlayerRoute() {
        if (player == null || !isLive()) return;
        PlaybackGate.State state = gate.state();
        if (state != PlaybackGate.State.VERIFYING_MUTED && state != PlaybackGate.State.PLAYING) return;
        try {
            if (connection == null || !connection.isSelectedRoute()) {
                finish("Call-route-lost-during-player", DisconnectCause.ERROR);
                return;
            }
            player.requestRouteCheck(); // Actual query stays on the MediaPlayer's own looper.
        } catch (RuntimeException error) {
            EventLog.error("actual player route", error);
            finish("player-route-error", DisconnectCause.ERROR);
        }
    }

    private boolean isPlayerIdentityCurrent(AsyncPlayer supplied) {
        return supplied != null && player == supplied && gate.isCurrent(supplied.token) && isLive();
    }

    /** AsyncPlayer marshals every listener call onto main before touching the gate or Telecom. */
    private final AsyncPlayer.Listener playerListener = new AsyncPlayer.Listener() {
        @Override public void onPrepared(AsyncPlayer supplied) {
            if (!isPlayerIdentityCurrent(supplied) || !supplied.accepts(token)) { supplied.stop(); return; }
            try {
                routeChanged(connection);
                long starting = now();
                if (!isPlayerIdentityCurrent(supplied) || !gate.preparedMuted(supplied.token, starting)) {
                    supplied.stop();
                    checkStopped();
                    return;
                }
                EventLog.add("background player prepared; authorizing muted actual-route verification");
                supplied.startMuted(starting + PlaybackGate.PLAY_LIMIT_MS);
                main.postDelayed(() -> {
                    if (isPlayerIdentityCurrent(supplied)) {
                        gate.tick(supplied.token, now());
                        checkStopped();
                    }
                }, PlaybackGate.PLAY_LIMIT_MS);
            } catch (RuntimeException error) {
                EventLog.error("prepared player policy", error);
                finish("player-prepared-policy-error", DisconnectCause.ERROR);
            }
        }

        @Override public void onRoute(AsyncPlayer supplied, boolean reported, boolean exactSco) {
            if (!isPlayerIdentityCurrent(supplied) || !supplied.accepts(token)) { supplied.stop(); return; }
            try {
                if (!gate.tick(supplied.token, now())) { checkStopped(); return; }
                if (connection == null || !connection.isSelectedRoute()) {
                    finish("Call-route-lost-during-player", DisconnectCause.ERROR);
                    return;
                }
                if (!reported && gate.state() == PlaybackGate.State.VERIFYING_MUTED) return;
                if (!gate.confirmPlayerRoute(supplied.token, exactSco, now())) { checkStopped(); return; }
                if (!audible) {
                    audible = true;
                    supplied.allowAudible(); // Worker checks identity/deadline/current SCO again before volume.
                    EventLog.add("actual player SCO snapshot verified; bounded unmute requested");
                }
            } catch (RuntimeException error) {
                EventLog.error("background route policy", error);
                finish("player-route-policy-error", DisconnectCause.ERROR);
            }
        }

        @Override public void onAudible(AsyncPlayer supplied) {
            if (!isPlayerIdentityCurrent(supplied) || !supplied.accepts(token)) { supplied.stop(); return; }
            EventLog.add("background exact-SCO player volume=0.5 (not proof of audible sound)");
        }

        @Override public void onTerminal(AsyncPlayer supplied, String reason, Throwable error) {
            // The worker cancels its ticket during release; terminal messages still require identity/token.
            if (!isPlayerIdentityCurrent(supplied)) { supplied.stop(); return; }
            if (error != null) EventLog.error("background player", error);
            finish(reason, "media-completed".equals(reason) ? DisconnectCause.LOCAL : DisconnectCause.ERROR);
        }

        @Override public void onReleased(AsyncPlayer supplied) {
            if (releasingPlayer != supplied) return;
            releasingPlayer = null; // Only retired-resource bookkeeping; never changes active call/gate.
            if (gate.isCurrent(supplied.token)) EventLog.add("background player cleanup completed");
        }
    };

    private final Runnable watchdog = new Runnable() {
        @Override public void run() {
            if (!isLive()) return;
            if (!gate.tick(token, now())) { checkStopped(); return; }
            try {
                requireBluetoothPermission();
                if (selected == null || selected.getBondState() != BluetoothDevice.BOND_BONDED) {
                    finish("selected-device-no-longer-bonded", DisconnectCause.ERROR);
                    return;
                }
                if (connection != null && gate.state() != PlaybackGate.State.WAITING_FOR_ANSWER) {
                    routeChanged(connection);
                }
            } catch (RuntimeException error) {
                EventLog.error("session monitor", error);
                finish("session-monitor-error", DisconnectCause.ERROR);
            }
            if (isLive()) main.postDelayed(this, 100);
        }
    };

    void stop(String reason) { run(() -> { if (isLive()) finish(reason, DisconnectCause.LOCAL); }); }
    void stopFromNotification(String suppliedToken) {
        if (gate.isCurrent(suppliedToken)) stop("notification-Stop");
    }
    void foregroundDestroyed(CallForegroundService service) {
        if (foreground == service && isLive()) finish("foreground-service-destroyed", DisconnectCause.ERROR);
    }
    void foregroundError(String suppliedToken, Throwable error) {
        if (!gate.isCurrent(suppliedToken) || !isLive()) return;
        EventLog.error("phoneCall foreground (no extra microphone permission requested)", error);
        finish("phoneCall-foreground-denied-see-permissions", DisconnectCause.ERROR);
    }

    private void checkStopped() {
        if (gate.state() == PlaybackGate.State.STOPPED && !ending) {
            finish(gate.stopReason(), DisconnectCause.ERROR);
        }
    }

    private void finish(String reason, int cause) {
        if (ending || token == null) return;
        ending = true;
        try {
            gate.stop(token, reason);
            main.removeCallbacks(watchdog);
            HfpPreflight retiringPreflight = hfpPreflight;
            hfpPreflight = null; // Late service/profile completion cannot enter a later session.
            if (retiringPreflight != null) retiringPreflight.cancel();
            incomingRequested = false;
            AsyncPlayer releasing = player;
            player = null;
            audible = false;
            if (releasing != null) {
                releasingPlayer = releasing;
                releasing.stop(); // Atomic invalidation + worker command; never waits for provider/release.
                EventLog.add("player invalidated; background release requested without waiting");
            }
            if (focus != null) {
                try { audioManager.abandonAudioFocusRequest(focus); }
                catch (RuntimeException error) { EventLog.error("focus abandon", error); }
                focus = null;
            }
            if (deviceObserverRegistered) {
                try { audioManager.unregisterAudioDeviceCallback(deviceObserver); }
                catch (RuntimeException error) { EventLog.error("device observer removal", error); }
                deviceObserverRegistered = false;
            }
            deviceObserver = null;
            GarminConnection closing = connection;
            connection = null; // Invalidate Connection callbacks before disconnect/destroy.
            if (closing != null) {
                try { closing.setDisconnected(new DisconnectCause(cause)); }
                catch (RuntimeException error) { EventLog.error("Connection disconnect", error); }
                try { closing.destroy(); }
                catch (RuntimeException error) { EventLog.error("Connection destroy", error); }
            }
            CallForegroundService service = foreground;
            foreground = null;
            if (service != null) service.endForeground();
            incomingUiAllowed = false;
            clearSourceAndDevice();
            EventLog.add("session stopped: " + gate.stopReason());
        } finally { ending = false; }
    }

    private void clearSourceAndDevice() {
        source = null;
        selected = null;
        selectedName = null;
        selectedAddress = null;
    }
}
