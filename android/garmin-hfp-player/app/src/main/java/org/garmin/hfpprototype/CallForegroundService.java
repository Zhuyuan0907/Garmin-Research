package org.garmin.hfpprototype;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Person;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;

/** Started only by the visible start-test button; notification actions target this existing service. */
public final class CallForegroundService extends Service {
    static final String ACTION_START = "org.garmin.hfpprototype.START";
    static final String ACTION_STOP = "org.garmin.hfpprototype.STOP";
    static final String ACTION_ANSWER = "org.garmin.hfpprototype.ANSWER";
    private static final String CHANNEL = "garmin_local_test_calls";
    private static final int NOTICE = 1;
    private String activeToken;
    private boolean started;

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        TestSession session = TestSession.get(this);
        if (intent == null) { if (!started) stopSelf(); return START_NOT_STICKY; }
        String supplied = intent.getStringExtra(TestSession.EXTRA_TOKEN);
        if (ACTION_STOP.equals(intent.getAction())) {
            session.stopFromNotification(supplied);
            if (!started) stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_ANSWER.equals(intent.getAction())) {
            session.answerFromNotification(supplied);
            if (!started) stopSelf();
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(intent.getAction()) || supplied == null
                || !supplied.equals(session.token()) || !session.isLive()) {
            if (!started) stopSelf();
            return START_NOT_STICKY;
        }
        if (started) return START_NOT_STICKY;
        activeToken = supplied;
        try {
            NotificationManager manager = getSystemService(NotificationManager.class);
            NotificationChannel channel = new NotificationChannel(CHANNEL,
                    "Garmin 本機通話試驗", NotificationManager.IMPORTANCE_HIGH);
            channel.setSound(null, null); // Never add ringtone audio or vibration automatically.
            channel.enableVibration(false);
            manager.createNotificationChannel(channel);
            if (manager.getNotificationChannel(CHANNEL).getImportance() == NotificationManager.IMPORTANCE_NONE) {
                throw new SecurityException();
            }
            if (Build.VERSION.SDK_INT >= 33
                    && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                // Applies ONLY to CallStyle + MANAGE_OWN_CALLS + registered self-managed account.
                EventLog.add("POST_NOTIFICATIONS absent: using self-managed CallStyle exemption only");
            }
            Notification notification = buildNotification();
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(NOTICE, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL);
            } else startForeground(NOTICE, notification);
            started = true;
            EventLog.add("phoneCall foreground ready; no microphone permission/type");
            // No document I/O/Telecom call before startForeground: satisfy its startup deadline.
            session.foregroundReady(this, activeToken);
        } catch (RuntimeException error) {
            session.foregroundError(activeToken, error);
            endForeground();
        }
        return START_NOT_STICKY; // Never resurrect an experiment or incoming call after process death.
    }

    private PendingIntent command(String action, int requestCode) {
        Intent intent = new Intent(this, CallForegroundService.class).setAction(action)
                // PendingIntent identity includes data; an old notification keeps its old token.
                .setData(new Uri.Builder().scheme("garminmusic").authority("action")
                        .appendPath(activeToken).appendPath(action).build())
                .putExtra(TestSession.EXTRA_TOKEN, activeToken);
        return PendingIntent.getService(this, requestCode, intent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    private Notification buildNotification() {
        TestSession session = TestSession.get(this);
        PendingIntent stop = command(ACTION_STOP, 1);
        PendingIntent answer = command(ACTION_ANSWER, 2);
        PendingIntent open = PendingIntent.getActivity(this, 3,
                new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification.Builder builder = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_media_play)
                .setContentTitle("Garmin 本機音檔試驗")
                .setContentText(session.status())
                .setCategory(Notification.CATEGORY_CALL)
                .setOngoing(true).setOnlyAlertOnce(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setContentIntent(open)
                .addAction(new Notification.Action.Builder(android.R.drawable.ic_menu_close_clear_cancel,
                        "Stop", stop).build());
        if (Build.VERSION.SDK_INT >= 31) {
            Person caller = new Person.Builder().setName("Garmin 本機試驗").build();
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE);
            builder.setStyle(session.notificationIsIncoming()
                    ? Notification.CallStyle.forIncomingCall(caller, stop, answer)
                    : Notification.CallStyle.forOngoingCall(caller, stop));
        } else if (session.notificationIsIncoming()) {
            builder.addAction(new Notification.Action.Builder(android.R.drawable.ic_menu_call,
                    "接聽", answer).build());
        }
        return builder.build();
    }

    void refreshNotification() {
        if (!started) return;
        try { getSystemService(NotificationManager.class).notify(NOTICE, buildNotification()); }
        catch (RuntimeException error) { TestSession.get(this).foregroundError(activeToken, error); }
    }

    void endForeground() {
        started = false;
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public void onDestroy() {
        TestSession.get(this).foregroundDestroyed(this);
        super.onDestroy();
    }
}
