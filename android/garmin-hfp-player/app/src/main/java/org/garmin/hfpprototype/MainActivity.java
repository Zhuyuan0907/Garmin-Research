package org.garmin.hfpprototype;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;

/** Deliberately simple visible UI. No background launch, microphone input, or outgoing call UI. */
public final class MainActivity extends Activity {
    private static final int PICK_AUDIO = 1;
    private static final int PERMISSIONS = 2;
    private final Handler main = new Handler(Looper.getMainLooper());
    private TestSession session;
    private Uri source;
    private BluetoothDevice chosen;
    private TextView status;
    private TextView sourceStatus;
    private TextView deviceStatus;
    private TextView log;
    private Button start;
    private Button answer;
    private Button play;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        session = TestSession.get(this);
        String savedUri = getSharedPreferences("local-source", MODE_PRIVATE).getString("uri", null);
        if (savedUri != null) source = Uri.parse(savedUri);

        ScrollView scroll = new ScrollView(this);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (16 * getResources().getDisplayMetrics().density);
        content.setPadding(padding, padding, padding, padding);
        scroll.addView(content);
        text(content, "Garmin HFP 本機音檔試驗", 22);
        text(content, "手機端實驗原型。先配對並選定 Garmin，再建立本機來電。接聽及路由確認後，"
                + "請明確按播放；包含靜音驗證最多 10 秒。沒有真實電話、麥克風或網路功能。"
                + "路由回報不等於 Garmin 喇叭已出聲。", 16);
        status = text(content, "", 16);
        button(content, "通知／已配對裝置權限", view -> requestVisiblePermissions());
        sourceStatus = text(content, source == null ? "尚未選擇本機音檔" : "已有保存的音檔文件授權", 16);
        button(content, "選擇本機音檔", view -> {
            if (session.isLive()) { EventLog.add("source change refused during test"); return; }
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("audio/*")
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .putExtra(Intent.EXTRA_LOCAL_ONLY, true)
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
            try { startActivityForResult(intent, PICK_AUDIO); }
            catch (RuntimeException error) { EventLog.error("document picker", error); }
        });
        deviceStatus = text(content, "尚未選擇這台 Garmin", 16);
        button(content, "選擇已配對的 Garmin（不掃描／不配對）", view -> chooseBondedDevice());
        start = button(content, "建立本機來電試驗", view -> session.begin(source, chosen));
        answer = button(content, "在手機接聽（亦可由 Garmin 接聽）", view -> session.answerFromVisibleUi());
        play = button(content, "播放最多 10 秒", view -> session.playFromVisibleUi());
        button(content, "Stop／結束本次試驗", view -> session.stop("visible-Stop"));
        text(content, "事件（最多 160 筆；不記錄 Bluetooth 位址、電話簿或音檔 URI）", 14);
        log = text(content, "", 12);
        log.setTextIsSelectable(true);
        setContentView(scroll);
    }

    private TextView text(LinearLayout parent, String value, int size) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextSize(size);
        text.setPadding(0, 8, 0, 8);
        parent.addView(text);
        return text;
    }

    private Button button(LinearLayout parent, String title, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(title);
        button.setOnClickListener(listener);
        parent.addView(button);
        return button;
    }

    private void requestVisiblePermissions() {
        List<String> missing = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= 31 && checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) missing.add(Manifest.permission.BLUETOOTH_CONNECT);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) missing.add(Manifest.permission.POST_NOTIFICATIONS);
        if (missing.isEmpty()) { EventLog.add("requested permissions already granted"); return; }
        requestPermissions(missing.toArray(new String[0]), PERMISSIONS);
    }

    private void chooseBondedDevice() {
        if (session.isLive()) { EventLog.add("device change refused during test"); return; }
        if (Build.VERSION.SDK_INT >= 31 && checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) {
            EventLog.add("selection refused: grant Bluetooth connect permission first");
            return;
        }
        try {
            BluetoothManager manager = getSystemService(BluetoothManager.class);
            BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
            if (adapter == null || !adapter.isEnabled()) { EventLog.add("Bluetooth unavailable or disabled"); return; }
            List<BluetoothDevice> devices = new ArrayList<>(adapter.getBondedDevices());
            if (devices.isEmpty()) { EventLog.add("no bonded devices; pair Garmin in Android settings first"); return; }
            String[] labels = new String[devices.size()];
            for (int i = 0; i < devices.size(); i++) {
                String name = devices.get(i).getName();
                labels[i] = (i + 1) + ". " + (name == null ? "無名稱（新版 route 會拒絕）" : name);
            }
            new AlertDialog.Builder(this).setTitle("請明確選擇這台 Garmin")
                    .setItems(labels, (dialog, which) -> {
                        if (session.isLive()) return;
                        chosen = devices.get(which);
                        deviceStatus.setText("已選擇：" + labels[which]);
                        EventLog.add("user selected one bonded device; name/address omitted from log");
                    }).setNegativeButton("取消", null).show();
        } catch (RuntimeException error) { EventLog.error("bonded-device selection", error); }
    }

    @Override public void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != PICK_AUDIO || result != RESULT_OK || data == null || data.getData() == null) return;
        if (session.isLive()) { EventLog.add("document result ignored while test is active"); return; }
        Uri uri = data.getData();
        try {
            if (!"content".equals(uri.getScheme()) || uri.getAuthority() == null) {
                throw new IllegalArgumentException();
            }
            // Save the system grant only. Provider queries belong to the one background player job.
            int grant = data.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION;
            if (grant == 0) throw new SecurityException();
            getContentResolver().takePersistableUriPermission(uri, grant);
            Uri previous = source;
            source = uri;
            getSharedPreferences("local-source", MODE_PRIVATE).edit().putString("uri", uri.toString()).apply();
            if (previous != null && !previous.equals(uri)) {
                try { getContentResolver().releasePersistableUriPermission(previous, Intent.FLAG_GRANT_READ_URI_PERMISSION); }
                catch (RuntimeException ignored) { }
            }
            sourceStatus.setText("已保存音檔授權；按播放時在背景檢查文件");
            EventLog.add("persisted local document read grant; URI omitted");
        } catch (RuntimeException error) { EventLog.error("local document grant", error); }
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (request != PERMISSIONS) return;
        for (int i = 0; i < permissions.length; i++) {
            boolean granted = i < results.length && results[i] == PackageManager.PERMISSION_GRANTED;
            EventLog.add("permission " + permissions[i] + " granted=" + granted);
        }
    }

    private final Runnable render = new Runnable() {
        @Override public void run() {
            status.setText(session.status());
            start.setEnabled(session.canStart() && source != null && chosen != null);
            answer.setEnabled(session.canAnswer());
            play.setEnabled(session.canPlay());
            log.setText(EventLog.snapshot());
            main.postDelayed(this, 500);
        }
    };

    @Override public void onResume() { super.onResume(); main.post(render); }
    @Override public void onPause() { main.removeCallbacks(render); super.onPause(); }
    // The foreground call continues under its deadlines if this Activity closes; Stop stays in notification.
}
