package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/

import android.annotation.TargetApi;
import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.TrafficStats;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.Process;
import android.os.SystemClock;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyManager;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.util.Log;
import android.util.TypedValue;
import android.widget.RemoteViews;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.preference.PreferenceManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.net.ssl.HttpsURLConnection;

public class ServiceSinkhole extends AbstractServiceSinkhole implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Service";

    private volatile Looper statsLooper;
    private volatile StatsHandler statsHandler;

    private static final int NOTIFY_ENFORCING = 1;
    private static final int NOTIFY_WAITING = 2;
    private static final int NOTIFY_DISABLED = 3;
    private static final int NOTIFY_AUTOSTART = 4;
    private static final int NOTIFY_ERROR = 5;
    private static final int NOTIFY_TRAFFIC = 6;
    private static final int NOTIFY_UPDATE = 7;
    public static final int NOTIFY_EXTERNAL = 8;
    public static final int NOTIFY_DOWNLOAD = 9;

    private static final int MSG_STATS_START = 1;
    private static final int MSG_STATS_STOP = 2;
    private static final int MSG_STATS_UPDATE = 3;
    private static final String RESTART_BROADCAST = "eu.faircode.netguard.Restart";

    public static void setPcap(boolean enabled, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        int record_size = 64;
        try {
            String r = prefs.getString("pcap_record_size", null);
            if (TextUtils.isEmpty(r))
                r = "64";
            record_size = Integer.parseInt(r);
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        int file_size = 2 * 1024 * 1024;
        try {
            String f = prefs.getString("pcap_file_size", null);
            if (TextUtils.isEmpty(f))
                f = "2";
            file_size = Integer.parseInt(f) * 1024 * 1024;
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        File pcap = (enabled ? new File(context.getDir("data", MODE_PRIVATE), "netguard.pcap") : null);
        jni_pcap(pcap == null ? null : pcap.getAbsolutePath(), record_size, file_size);
    }

    private final class CommandHandler extends AbstractServiceSinkhole.CommandHandler {
        public int queue = 0;

        public CommandHandler(Looper looper) {
            super(looper);
        }

        protected void reportQueueSize() {
            Intent ruleset = new Intent(ActivityMain.ACTION_QUEUE_CHANGED);
            ruleset.putExtra(ActivityMain.EXTRA_SIZE, queue);
            LocalBroadcastManager.getInstance(ServiceSinkhole.this).sendBroadcast(ruleset);
        }

        protected void handleCommand(Intent intent, SharedPreferences prefs, Command cmd) {
            try {
                switch (cmd) {
                    case run:
                        break;

                    case start:
                        start();
                        break;

                    case reload:
                        reload(intent.getBooleanExtra(EXTRA_INTERACTIVE, false));
                        break;

                    case stop:
                        stop(temporarilyStopped);
                        break;

                    case stats:
                        statsHandler.sendEmptyMessage(MSG_STATS_STOP);
                        statsHandler.sendEmptyMessage(MSG_STATS_START);
                        break;

                    case householding:
                        householding(intent);
                        break;

                    case watchdog:
                        watchdog(intent);
                        break;

                    default:
                        Log.e(TAG, "Unknown command=" + cmd);
                }

                if (cmd == Command.start || cmd == Command.reload || cmd == Command.stop) {
                    // Update main view
                    Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
                    ruleset.putExtra(ActivityMain.EXTRA_CONNECTED, cmd == Command.stop ? false : last_connected);
                    ruleset.putExtra(ActivityMain.EXTRA_METERED, cmd == Command.stop ? false : last_metered);
                    LocalBroadcastManager.getInstance(ServiceSinkhole.this).sendBroadcast(ruleset);

                    // Update widgets
                    WidgetMain.updateWidgets(ServiceSinkhole.this);
                }

                // Stop service if needed
                if (!commandHandler.hasMessages(Command.start.ordinal()) &&
                        !commandHandler.hasMessages(Command.reload.ordinal()) &&
                        !prefs.getBoolean("enabled", false) &&
                        !prefs.getBoolean("show_stats", false))
                    stopForeground(true);

                // Request garbage collection
                System.gc();
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

                if (cmd == Command.start || cmd == Command.reload) {
                    if (VpnService.prepare(ServiceSinkhole.this) == null) {
                        Log.w(TAG, "VPN prepared connected=" + last_connected);
                        if (last_connected && !(ex instanceof StartFailedException)) {
                            //showAutoStartNotification();
                            if (!Util.isPlayStoreInstall(ServiceSinkhole.this))
                                showErrorNotification(ex.toString());
                        }
                        // Retried on connectivity change
                    } else {
                        showErrorNotification(ex.toString());

                        // Disable firewall
                        if (!(ex instanceof StartFailedException)) {
                            prefs.edit().putBoolean("enabled", false).apply();
                            WidgetMain.updateWidgets(ServiceSinkhole.this);
                        }
                    }
                } else
                    showErrorNotification(ex.toString());
            }
        }

        protected void start() {
            if (vpn == null) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
                state = State.enforcing;
                Log.d(TAG, "Start foreground state=" + state.toString());

                List<Rule> listRule = Rule.getRules(true, ServiceSinkhole.this);
                List<Rule> listAllowed = getAllowedRules(listRule);

                last_builder = getBuilder(listAllowed, listRule);
                vpn = startVPN(last_builder);
                if (vpn == null)
                    throw new StartFailedException(getString((R.string.msg_start_failed)));

                startNative(vpn, listAllowed, listRule);

                removeWarningNotifications();
                updateEnforcingNotification(listAllowed.size(), listRule.size());
            }
        }

        protected void reload(boolean interactive) {
            List<Rule> listRule = Rule.getRules(true, ServiceSinkhole.this);

            // Check if rules needs to be reloaded
            if (interactive) {
                boolean process = false;
                for (Rule rule : listRule) {
                    boolean blocked = (last_metered ? rule.other_blocked : rule.wifi_blocked);
                    boolean screen = (last_metered ? rule.screen_other : rule.screen_wifi);
                    if (blocked && screen) {
                        process = true;
                        break;
                    }
                }
                if (!process) {
                    Log.i(TAG, "No changed rules on interactive state change");
                    return;
                }
            }

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);

            if (state != State.enforcing) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
                state = State.enforcing;
                Log.d(TAG, "Start foreground state=" + state.toString());
            }

            List<Rule> listAllowed = getAllowedRules(listRule);
            ServiceSinkhole.Builder builder = getBuilder(listAllowed, listRule);

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) {
                last_builder = builder;
                Log.i(TAG, "Legacy restart");

                if (vpn != null) {
                    stopNative(vpn);
                    stopVPN(vpn);
                    vpn = null;
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ignored) {
                    }
                }
                vpn = startVPN(last_builder);

            } else {
                if (vpn != null && prefs.getBoolean("filter", false) && builder.equals(last_builder)) {
                    Log.i(TAG, "Native restart");
                    stopNative(vpn);

                } else {
                    last_builder = builder;

                    boolean handover = prefs.getBoolean("handover", false);
                    Log.i(TAG, "VPN restart handover=" + handover);

                    if (handover) {
                        // Attempt seamless handover
                        ParcelFileDescriptor prev = vpn;
                        vpn = startVPN(builder);

                        if (prev != null && vpn == null) {
                            Log.w(TAG, "Handover failed");
                            stopNative(prev);
                            stopVPN(prev);
                            prev = null;
                            try {
                                Thread.sleep(3000);
                            } catch (InterruptedException ignored) {
                            }
                            vpn = startVPN(last_builder);
                            if (vpn == null)
                                throw new IllegalStateException("Handover failed");
                        }

                        if (prev != null) {
                            stopNative(prev);
                            stopVPN(prev);
                        }
                    } else {
                        if (vpn != null) {
                            stopNative(vpn);
                            stopVPN(vpn);
                        }

                        vpn = startVPN(builder);
                    }
                }
            }

            if (vpn == null)
                throw new StartFailedException(getString((R.string.msg_start_failed)));

            startNative(vpn, listAllowed, listRule);

            removeWarningNotifications();
            updateEnforcingNotification(listAllowed.size(), listRule.size());
        }

        protected void stop(boolean temporary) {
            if (vpn != null) {
                stopNative(vpn);
                stopVPN(vpn);
                vpn = null;
                unprepare();
            }
            if (state == State.enforcing && !temporary) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                last_allowed = -1;
                last_blocked = -1;
                last_hosts = -1;

                stopForeground(true);

                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                if (prefs.getBoolean("show_stats", false)) {
                    startForeground(NOTIFY_WAITING, getWaitingNotification());
                    state = State.waiting;
                    Log.d(TAG, "Start foreground state=" + state.toString());
                } else {
                    state = State.none;
                    stopSelf();
                }
            }
        }

        protected void householding(Intent intent) {
            // Keep log records for three days
            DatabaseHelper.getInstance(ServiceSinkhole.this).cleanupLog(new Date().getTime() - 3 * 24 * 3600 * 1000L);

            // Clear expired DNS records
            DatabaseHelper.getInstance(ServiceSinkhole.this).cleanupDns();

            // Check for update
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            if (!Util.isPlayStoreInstall(ServiceSinkhole.this) &&
                    Util.hasValidFingerprint(ServiceSinkhole.this) &&
                    prefs.getBoolean("update_check", true))
                checkUpdate();
        }

        private void checkUpdate() {
            StringBuilder json = new StringBuilder();
            HttpsURLConnection urlConnection = null;
            try {
                URL url = new URL(BuildConfig.GITHUB_LATEST_API);
                urlConnection = (HttpsURLConnection) url.openConnection();
                BufferedReader br = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));

                String line;
                while ((line = br.readLine()) != null)
                    json.append(line);

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            } finally {
                if (urlConnection != null)
                    urlConnection.disconnect();
            }

            try {
                JSONObject jroot = new JSONObject(json.toString());
                if (jroot.has("tag_name") && jroot.has("html_url") && jroot.has("assets")) {
                    String url = jroot.getString("html_url");
                    JSONArray jassets = jroot.getJSONArray("assets");
                    if (jassets.length() > 0) {
                        JSONObject jasset = jassets.getJSONObject(0);
                        if (jasset.has("name")) {
                            String version = jroot.getString("tag_name");
                            String name = jasset.getString("name");
                            Log.i(TAG, "Tag " + version + " name " + name + " url " + url);

                            Version current = new Version(Util.getSelfVersionName(ServiceSinkhole.this));
                            Version available = new Version(version);
                            if (current.compareTo(available) < 0) {
                                Log.i(TAG, "Update available from " + current + " to " + available);
                                showUpdateNotification(name, url);
                            } else
                                Log.i(TAG, "Up-to-date current version " + current);
                        }
                    }
                }
            } catch (JSONException ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }
    }

    private final class LogHandler extends AbstractServiceSinkhole.LogHandler {

        public LogHandler(Looper looper) {
            super(looper);
        }

        protected void log(Packet packet, int connection, boolean interactive) {
            // Get settings
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            boolean log = prefs.getBoolean("log", false);
            boolean log_app = prefs.getBoolean("log_app", false);

            DatabaseHelper dh = DatabaseHelper.getInstance(ServiceSinkhole.this);

            // Get real name
            String dname = dh.getQName(packet.uid, packet.daddr);

            // Traffic log
            if (log)
                dh.insertLog(packet, dname, connection, interactive);

            // Application log
            if (log_app && packet.uid >= 0 &&
                    !(packet.uid == 0 && (packet.protocol == 6 || packet.protocol == 17) && packet.dport == 53)) {
                if (!(packet.protocol == 6 /* TCP */ || packet.protocol == 17 /* UDP */))
                    packet.dport = 0;
                if (dh.updateAccess(packet, dname, -1)) {
                    lock.readLock().lock();
                    if (!mapNotify.containsKey(packet.uid) || mapNotify.get(packet.uid))
                        showAccessNotification(packet.uid);
                    lock.readLock().unlock();
                }
            }
        }
    }

    private final class StatsHandler extends Handler {
        private boolean stats = false;
        private long when;

        private long t = -1;
        private long tx = -1;
        private long rx = -1;

        private List<Long> gt = new ArrayList<>();
        private List<Float> gtx = new ArrayList<>();
        private List<Float> grx = new ArrayList<>();

        private HashMap<Integer, Long> mapUidBytes = new HashMap<>();

        public StatsHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            try {
                switch (msg.what) {
                    case MSG_STATS_START:
                        startStats();
                        break;

                    case MSG_STATS_STOP:
                        stopStats();
                        break;

                    case MSG_STATS_UPDATE:
                        updateStats();
                        break;

                    default:
                        Log.e(TAG, "Unknown stats message=" + msg.what);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }

        private void startStats() {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            boolean enabled = (!stats && prefs.getBoolean("show_stats", false));
            Log.i(TAG, "Stats start enabled=" + enabled);
            if (enabled) {
                when = new Date().getTime();
                t = -1;
                tx = -1;
                rx = -1;
                gt.clear();
                gtx.clear();
                grx.clear();
                mapUidBytes.clear();
                stats = true;
                updateStats();
            }
        }

        private void stopStats() {
            Log.i(TAG, "Stats stop");
            stats = false;
            this.removeMessages(MSG_STATS_UPDATE);
            if (state == State.stats) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                stopForeground(true);
                state = State.none;
            } else
                NotificationManagerCompat.from(ServiceSinkhole.this).cancel(NOTIFY_TRAFFIC);
        }

        private void updateStats() {
            RemoteViews remoteViews = new RemoteViews(getPackageName(), R.layout.traffic);
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            long frequency = Long.parseLong(prefs.getString("stats_frequency", "1000"));
            long samples = Long.parseLong(prefs.getString("stats_samples", "90"));
            boolean filter = prefs.getBoolean("filter", false);
            boolean show_top = prefs.getBoolean("show_top", false);
            int loglevel = Integer.parseInt(prefs.getString("loglevel", Integer.toString(Log.WARN)));

            // Schedule next update
            this.sendEmptyMessageDelayed(MSG_STATS_UPDATE, frequency);

            long ct = SystemClock.elapsedRealtime();

            // Cleanup
            while (gt.size() > 0 && ct - gt.get(0) > samples * 1000) {
                gt.remove(0);
                gtx.remove(0);
                grx.remove(0);
            }

            // Calculate network speed
            float txsec = 0;
            float rxsec = 0;
            long ttx = TrafficStats.getTotalTxBytes();
            long trx = TrafficStats.getTotalRxBytes();
            if (filter) {
                ttx -= TrafficStats.getUidTxBytes(Process.myUid());
                trx -= TrafficStats.getUidRxBytes(Process.myUid());
                if (ttx < 0)
                    ttx = 0;
                if (trx < 0)
                    trx = 0;
            }
            if (t > 0 && tx > 0 && rx > 0) {
                float dt = (ct - t) / 1000f;
                txsec = (ttx - tx) / dt;
                rxsec = (trx - rx) / dt;
                gt.add(ct);
                gtx.add(txsec);
                grx.add(rxsec);
            }

            // Calculate application speeds
            if (show_top) {
                if (mapUidBytes.size() == 0) {
                    for (ApplicationInfo ainfo : getPackageManager().getInstalledApplications(0))
                        if (ainfo.uid != Process.myUid())
                            mapUidBytes.put(ainfo.uid, TrafficStats.getUidTxBytes(ainfo.uid) + TrafficStats.getUidRxBytes(ainfo.uid));

                } else if (t > 0) {
                    TreeMap<Float, Integer> mapSpeedUid = new TreeMap<>(new Comparator<Float>() {
                        @Override
                        public int compare(Float value, Float other) {
                            return -value.compareTo(other);
                        }
                    });
                    float dt = (ct - t) / 1000f;
                    for (int uid : mapUidBytes.keySet()) {
                        long bytes = TrafficStats.getUidTxBytes(uid) + TrafficStats.getUidRxBytes(uid);
                        float speed = (bytes - mapUidBytes.get(uid)) / dt;
                        if (speed > 0) {
                            mapSpeedUid.put(speed, uid);
                            mapUidBytes.put(uid, bytes);
                        }
                    }

                    StringBuilder sb = new StringBuilder();
                    int i = 0;
                    for (float speed : mapSpeedUid.keySet()) {
                        if (i++ >= 3)
                            break;
                        if (speed < 1000 * 1000)
                            sb.append(getString(R.string.msg_kbsec, speed / 1000));
                        else
                            sb.append(getString(R.string.msg_mbsec, speed / 1000 / 1000));
                        sb.append(' ');
                        List<String> apps = Util.getApplicationNames(mapSpeedUid.get(speed), ServiceSinkhole.this);
                        sb.append(apps.size() > 0 ? apps.get(0) : "?");
                        sb.append("\r\n");
                    }
                    if (sb.length() > 0)
                        sb.setLength(sb.length() - 2);
                    remoteViews.setTextViewText(R.id.tvTop, sb.toString());
                }
            }

            t = ct;
            tx = ttx;
            rx = trx;

            // Create bitmap
            int height = Util.dips2pixels(96, ServiceSinkhole.this);
            int width = Util.dips2pixels(96 * 5, ServiceSinkhole.this);
            Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);

            // Create canvas
            Canvas canvas = new Canvas(bitmap);
            canvas.drawColor(Color.TRANSPARENT);

            // Determine max
            float max = 0;
            long xmax = 0;
            float ymax = 0;
            for (int i = 0; i < gt.size(); i++) {
                long t = gt.get(i);
                float tx = gtx.get(i);
                float rx = grx.get(i);
                if (t > xmax)
                    xmax = t;
                if (tx > max)
                    max = tx;
                if (rx > max)
                    max = rx;
                if (tx > ymax)
                    ymax = tx;
                if (rx > ymax)
                    ymax = rx;
            }

            // Build paths
            Path ptx = new Path();
            Path prx = new Path();
            for (int i = 0; i < gtx.size(); i++) {
                float x = width - width * (xmax - gt.get(i)) / 1000f / samples;
                float ytx = height - height * gtx.get(i) / ymax;
                float yrx = height - height * grx.get(i) / ymax;
                if (i == 0) {
                    ptx.moveTo(x, ytx);
                    prx.moveTo(x, yrx);
                } else {
                    ptx.lineTo(x, ytx);
                    prx.lineTo(x, yrx);
                }
            }

            // Build paint
            Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
            paint.setStyle(Paint.Style.STROKE);

            // Draw scale line
            paint.setStrokeWidth(Util.dips2pixels(1, ServiceSinkhole.this));
            paint.setColor(ContextCompat.getColor(ServiceSinkhole.this, R.color.colorGrayed));
            float y = height / 2;
            canvas.drawLine(0, y, width, y, paint);

            // Draw paths
            paint.setStrokeWidth(Util.dips2pixels(2, ServiceSinkhole.this));
            paint.setColor(ContextCompat.getColor(ServiceSinkhole.this, R.color.colorSend));
            canvas.drawPath(ptx, paint);
            paint.setColor(ContextCompat.getColor(ServiceSinkhole.this, R.color.colorReceive));
            canvas.drawPath(prx, paint);

            // Update remote view
            remoteViews.setImageViewBitmap(R.id.ivTraffic, bitmap);
            if (txsec < 1000 * 1000)
                remoteViews.setTextViewText(R.id.tvTx, getString(R.string.msg_kbsec, txsec / 1000));
            else
                remoteViews.setTextViewText(R.id.tvTx, getString(R.string.msg_mbsec, txsec / 1000 / 1000));

            if (rxsec < 1000 * 1000)
                remoteViews.setTextViewText(R.id.tvRx, getString(R.string.msg_kbsec, rxsec / 1000));
            else
                remoteViews.setTextViewText(R.id.tvRx, getString(R.string.msg_mbsec, rxsec / 1000 / 1000));

            if (max < 1000 * 1000)
                remoteViews.setTextViewText(R.id.tvMax, getString(R.string.msg_kbsec, max / 2 / 1000));
            else
                remoteViews.setTextViewText(R.id.tvMax, getString(R.string.msg_mbsec, max / 2 / 1000 / 1000));

            // Show session/file count
            if (filter && loglevel <= Log.WARN) {
                int[] count = jni_get_stats(jni_context);
                remoteViews.setTextViewText(R.id.tvSessions, count[0] + "/" + count[1] + "/" + count[2]);
                remoteViews.setTextViewText(R.id.tvFiles, count[3] + "/" + count[4]);
            } else {
                remoteViews.setTextViewText(R.id.tvSessions, "");
                remoteViews.setTextViewText(R.id.tvFiles, "");
            }

            // Show notification
            Intent main = new Intent(ServiceSinkhole.this, ActivityMain.class);
            PendingIntent pi = PendingIntent.getActivity(ServiceSinkhole.this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

            TypedValue tv = new TypedValue();
            getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(ServiceSinkhole.this, "notify");
            builder.setWhen(when)
                    .setSmallIcon(R.drawable.ic_equalizer_white_24dp)
                    .setContent(remoteViews)
                    .setContentIntent(pi)
                    .setColor(tv.data)
                    .setOngoing(true)
                    .setAutoCancel(false);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
                builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                        .setVisibility(NotificationCompat.VISIBILITY_PUBLIC);

            if (state == State.none || state == State.waiting) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_TRAFFIC, builder.build());
                state = State.stats;
                Log.d(TAG, "Start foreground state=" + state.toString());
            } else
                NotificationManagerCompat.from(ServiceSinkhole.this).notify(NOTIFY_TRAFFIC, builder.build());
        }
    }

    protected void setBuildConfigureIntent(Builder builder){
        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);
    }

    protected void prepareUidIPFilters(String dname) {
        SharedPreferences lockdown = getSharedPreferences("lockdown", Context.MODE_PRIVATE);

        lock.writeLock().lock();

        if (dname == null) {
            mapUidIPFilters.clear();
            if (!IAB.isPurchased(ActivityPro.SKU_FILTER, ServiceSinkhole.this)) {
                lock.writeLock().unlock();
                return;
            }
        }

        try (Cursor cursor = DatabaseHelper.getInstance(ServiceSinkhole.this).getAccessDns(dname)) {
            int colUid = cursor.getColumnIndex("uid");
            int colVersion = cursor.getColumnIndex("version");
            int colProtocol = cursor.getColumnIndex("protocol");
            int colDAddr = cursor.getColumnIndex("daddr");
            int colResource = cursor.getColumnIndex("resource");
            int colDPort = cursor.getColumnIndex("dport");
            int colBlock = cursor.getColumnIndex("block");
            int colTime = cursor.getColumnIndex("time");
            int colTTL = cursor.getColumnIndex("ttl");
            while (cursor.moveToNext()) {
                int uid = cursor.getInt(colUid);
                int version = cursor.getInt(colVersion);
                int protocol = cursor.getInt(colProtocol);
                String daddr = cursor.getString(colDAddr);
                String dresource = (cursor.isNull(colResource) ? null : cursor.getString(colResource));
                int dport = cursor.getInt(colDPort);
                boolean block = (cursor.getInt(colBlock) > 0);
                long time = (cursor.isNull(colTime) ? new Date().getTime() : cursor.getLong(colTime));
                long ttl = (cursor.isNull(colTTL) ? 7 * 24 * 3600 * 1000L : cursor.getLong(colTTL));

                if (isLockedDown(last_metered)) {
                    String[] pkg = getPackageManager().getPackagesForUid(uid);
                    if (pkg != null && pkg.length > 0) {
                        if (!lockdown.getBoolean(pkg[0], false))
                            continue;
                    }
                }

                IPKey key = new IPKey(version, protocol, dport, uid);
                synchronized (mapUidIPFilters) {
                    if (!mapUidIPFilters.containsKey(key))
                        mapUidIPFilters.put(key, new HashMap());

                    try {
                        String name = (dresource == null ? daddr : dresource);
                        if (Util.isNumericAddress(name)) {
                            InetAddress iname = InetAddress.getByName(name);
                            if (version == 4 && !(iname instanceof Inet4Address))
                                continue;
                            if (version == 6 && !(iname instanceof Inet6Address))
                                continue;

                            boolean exists = mapUidIPFilters.get(key).containsKey(iname);
                            if (!exists || !mapUidIPFilters.get(key).get(iname).isBlocked()) {
                                IPRule rule = new IPRule(key, name + "/" + iname, block, time + ttl);
                                mapUidIPFilters.get(key).put(iname, rule);
                                if (exists)
                                    Log.w(TAG, "Address conflict " + key + " " + daddr + "/" + dresource);
                            } else if (exists) {
                                mapUidIPFilters.get(key).get(iname).updateExpires(time + ttl);
                                if (dname != null && ttl > 60 * 1000L)
                                    Log.w(TAG, "Address updated " + key + " " + daddr + "/" + dresource);
                            } else {
                                if (dname != null)
                                    Log.i(TAG, "Ignored " + key + " " + daddr + "/" + dresource + "=" + block);
                            }
                        } else
                            Log.w(TAG, "Address not numeric " + name);
                    } catch (UnknownHostException ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
                }
            }
        }

        lock.writeLock().unlock();
    }

    // Called from native code
    private void nativeExit(String reason) {
        Log.w(TAG, "Native exit reason=" + reason);
        if (reason != null) {
            showErrorNotification(reason);

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", false).apply();
            WidgetMain.updateWidgets(this);
        }
    }

    // Called from native code
    private void nativeError(int error, String message) {
        Log.w(TAG, "Native error " + error + ": " + message);
        showErrorNotification(message);
    }

    // Called from native code
    private void logPacket(Packet packet) {
        logHandler.queue(packet);
    }

    // Called from native code
    private void dnsResolved(ResourceRecord rr) {
        if (DatabaseHelper.getInstance(ServiceSinkhole.this).insertDns(rr)) {
            Log.i(TAG, "New IP " + rr);
            prepareUidIPFilters(rr.QName);
        }
    }

    // Called from native code
    private boolean isDomainBlocked(String name) {
        lock.readLock().lock();
        boolean blocked = (mapHostsBlocked.containsKey(name) && mapHostsBlocked.get(name));
        lock.readLock().unlock();
        return blocked;
    }

    // Called from native code
    @TargetApi(Build.VERSION_CODES.Q)
    private int getUidQ(int version, int protocol, String saddr, int sport, String daddr, int dport) {
        if (protocol != 6 /* TCP */ && protocol != 17 /* UDP */)
            return Process.INVALID_UID;

        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (cm == null)
            return Process.INVALID_UID;

        InetSocketAddress local = new InetSocketAddress(saddr, sport);
        InetSocketAddress remote = new InetSocketAddress(daddr, dport);

        Log.i(TAG, "Get uid local=" + local + " remote=" + remote);
        int uid = cm.getConnectionOwnerUid(protocol, local, remote);
        Log.i(TAG, "Get uid=" + uid);
        return uid;
    }

    // Called from native code
    private Allowed isAddressAllowed(Packet packet) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        lock.readLock().lock();

        packet.allowed = false;
        if (prefs.getBoolean("filter", false)) {
            // https://android.googlesource.com/platform/system/core/+/master/include/private/android_filesystem_config.h
            if (packet.protocol == 17 /* UDP */ && !prefs.getBoolean("filter_udp", false)) {
                // Allow unfiltered UDP
                packet.allowed = true;
                Log.i(TAG, "Allowing UDP " + packet);
            } else if (packet.uid < 2000 &&
                    !last_connected && isSupported(packet.protocol) && false) {
                // Allow system applications in disconnected state
                packet.allowed = true;
                Log.w(TAG, "Allowing disconnected system " + packet);
            } else if (packet.uid < 2000 &&
                    !mapUidKnown.containsKey(packet.uid) && isSupported(packet.protocol)) {
                // Allow unknown system traffic
                packet.allowed = true;
                Log.w(TAG, "Allowing unknown system " + packet);
            } else if (packet.uid == Process.myUid()) {
                // Allow self
                packet.allowed = true;
                Log.w(TAG, "Allowing self " + packet);
            } else {
                boolean filtered = false;
                IPKey key = new IPKey(packet.version, packet.protocol, packet.dport, packet.uid);
                if (mapUidIPFilters.containsKey(key))
                    try {
                        InetAddress iaddr = InetAddress.getByName(packet.daddr);
                        Map<InetAddress, IPRule> map = mapUidIPFilters.get(key);
                        if (map != null && map.containsKey(iaddr)) {
                            IPRule rule = map.get(iaddr);
                            if (rule.isExpired())
                                Log.i(TAG, "DNS expired " + packet + " rule " + rule);
                            else {
                                filtered = true;
                                packet.allowed = !rule.isBlocked();
                                Log.i(TAG, "Filtering " + packet +
                                        " allowed=" + packet.allowed + " rule " + rule);
                            }
                        }
                    } catch (UnknownHostException ex) {
                        Log.w(TAG, "Allowed " + ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }

                if (!filtered)
                    if (mapUidAllowed.containsKey(packet.uid))
                        packet.allowed = mapUidAllowed.get(packet.uid);
                    else
                        Log.w(TAG, "No rules for " + packet);
            }
        }

        Allowed allowed = null;
        if (packet.allowed) {
            if (mapForward.containsKey(packet.dport)) {
                Forward fwd = mapForward.get(packet.dport);
                if (fwd.ruid == packet.uid) {
                    allowed = new Allowed();
                } else {
                    allowed = new Allowed(fwd.raddr, fwd.rport);
                    packet.data = "> " + fwd.raddr + "/" + fwd.rport;
                }
            } else
                allowed = new Allowed();
        }

        lock.readLock().unlock();

        if (prefs.getBoolean("log", false) || prefs.getBoolean("log_app", false))
            if (packet.protocol != 6 /* TCP */ || !"".equals(packet.flags))
                if (packet.uid != Process.myUid())
                    logPacket(packet);

        return allowed;
    }

    // Called from native code
    private void accountUsage(Usage usage) {
        logHandler.account(usage);
    }

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(final Context context, final Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            executor.submit(new Runnable() {
                @Override
                public void run() {
                    AlarmManager am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
                    Intent i = new Intent(ACTION_SCREEN_OFF_DELAYED);
                    i.setPackage(context.getPackageName());
                    PendingIntent pi = PendingIntent.getBroadcast(context, 0, i, PendingIntent.FLAG_UPDATE_CURRENT);
                    am.cancel(pi);

                    try {
                        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                        int delay;
                        try {
                            delay = Integer.parseInt(prefs.getString("screen_delay", "0"));
                        } catch (NumberFormatException ignored) {
                            delay = 0;
                        }
                        boolean interactive = Intent.ACTION_SCREEN_ON.equals(intent.getAction());

                        if (interactive || delay == 0) {
                            last_interactive = interactive;
                            reload("interactive state changed", ServiceSinkhole.this, true);
                        } else {
                            if (ACTION_SCREEN_OFF_DELAYED.equals(intent.getAction())) {
                                last_interactive = interactive;
                                reload("interactive state changed", ServiceSinkhole.this, true);
                            } else {
                                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
                                    am.set(AlarmManager.RTC_WAKEUP, new Date().getTime() + delay * 60 * 1000L, pi);
                                else
                                    am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, new Date().getTime() + delay * 60 * 1000L, pi);
                            }
                        }

                        // Start/stop stats
                        statsHandler.sendEmptyMessage(
                                Util.isInteractive(ServiceSinkhole.this) ? MSG_STATS_START : MSG_STATS_STOP);
                    } catch (Throwable ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

                        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
                            am.set(AlarmManager.RTC_WAKEUP, new Date().getTime() + 15 * 1000L, pi);
                        else
                            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, new Date().getTime() + 15 * 1000L, pi);
                    }
                }
            });
        }
    };

    private BroadcastReceiver packageChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            try {
                if (Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction())) {
                    // Application added
                    Rule.clearCache(context);

                    if (!intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
                        // Show notification
                        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                        if (IAB.isPurchased(ActivityPro.SKU_NOTIFY, context) && prefs.getBoolean("install", true)) {
                            int uid = intent.getIntExtra(Intent.EXTRA_UID, -1);
                            notifyNewApplication(uid);
                        }
                    }

                    reload("package added", context, false);

                } else if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())) {
                    // Application removed
                    Rule.clearCache(context);

                    if (intent.getBooleanExtra(Intent.EXTRA_DATA_REMOVED, false)) {
                        // Remove settings
                        String packageName = intent.getData().getSchemeSpecificPart();
                        Log.i(TAG, "Deleting settings package=" + packageName);
                        context.getSharedPreferences("wifi", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("other", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("screen_other", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("roaming", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("lockdown", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("apply", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("notify", Context.MODE_PRIVATE).edit().remove(packageName).apply();

                        int uid = intent.getIntExtra(Intent.EXTRA_UID, 0);
                        if (uid > 0) {
                            DatabaseHelper dh = DatabaseHelper.getInstance(context);
                            dh.clearLog(uid);
                            dh.clearAccess(uid, false);

                            NotificationManagerCompat.from(context).cancel(uid); // installed notification
                            NotificationManagerCompat.from(context).cancel(uid + 10000); // access notification
                        }
                    }

                    reload("package deleted", context, false);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }
    };

    public void notifyNewApplication(int uid) {
        if (uid < 0)
            return;

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        try {
            // Get application name
            String name = TextUtils.join(", ", Util.getApplicationNames(uid, this));

            // Get application info
            PackageManager pm = getPackageManager();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages == null || packages.length < 1)
                throw new PackageManager.NameNotFoundException(Integer.toString(uid));
            boolean internet = Util.hasInternet(uid, this);

            // Build notification
            Intent main = new Intent(this, ActivityMain.class);
            main.putExtra(ActivityMain.EXTRA_REFRESH, true);
            main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
            PendingIntent pi = PendingIntent.getActivity(this, uid, main, PendingIntent.FLAG_UPDATE_CURRENT);

            TypedValue tv = new TypedValue();
            getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
            builder.setSmallIcon(R.drawable.ic_security_white_24dp)
                    .setContentIntent(pi)
                    .setColor(tv.data)
                    .setAutoCancel(true);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                builder.setContentTitle(name)
                        .setContentText(getString(R.string.msg_installed_n));
            else
                builder.setContentTitle(getString(R.string.app_name))
                        .setContentText(getString(R.string.msg_installed, name));

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
                builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                        .setVisibility(NotificationCompat.VISIBILITY_SECRET);

            // Get defaults
            SharedPreferences prefs_wifi = getSharedPreferences("wifi", Context.MODE_PRIVATE);
            SharedPreferences prefs_other = getSharedPreferences("other", Context.MODE_PRIVATE);
            boolean wifi = prefs_wifi.getBoolean(packages[0], prefs.getBoolean("whitelist_wifi", true));
            boolean other = prefs_other.getBoolean(packages[0], prefs.getBoolean("whitelist_other", true));

            // Build Wi-Fi action
            Intent riWifi = new Intent(this, ServiceSinkhole.class);
            riWifi.putExtra(ServiceSinkhole.EXTRA_COMMAND, ServiceSinkhole.Command.set);
            riWifi.putExtra(ServiceSinkhole.EXTRA_NETWORK, "wifi");
            riWifi.putExtra(ServiceSinkhole.EXTRA_UID, uid);
            riWifi.putExtra(ServiceSinkhole.EXTRA_PACKAGE, packages[0]);
            riWifi.putExtra(ServiceSinkhole.EXTRA_BLOCKED, !wifi);

            PendingIntent piWifi = PendingIntent.getService(this, uid, riWifi, PendingIntent.FLAG_UPDATE_CURRENT);
            NotificationCompat.Action wAction = new NotificationCompat.Action.Builder(
                    wifi ? R.drawable.wifi_on : R.drawable.wifi_off,
                    getString(wifi ? R.string.title_allow_wifi : R.string.title_block_wifi),
                    piWifi
            ).build();
            builder.addAction(wAction);

            // Build mobile action
            Intent riOther = new Intent(this, ServiceSinkhole.class);
            riOther.putExtra(ServiceSinkhole.EXTRA_COMMAND, ServiceSinkhole.Command.set);
            riOther.putExtra(ServiceSinkhole.EXTRA_NETWORK, "other");
            riOther.putExtra(ServiceSinkhole.EXTRA_UID, uid);
            riOther.putExtra(ServiceSinkhole.EXTRA_PACKAGE, packages[0]);
            riOther.putExtra(ServiceSinkhole.EXTRA_BLOCKED, !other);
            PendingIntent piOther = PendingIntent.getService(this, uid + 10000, riOther, PendingIntent.FLAG_UPDATE_CURRENT);
            NotificationCompat.Action oAction = new NotificationCompat.Action.Builder(
                    other ? R.drawable.other_on : R.drawable.other_off,
                    getString(other ? R.string.title_allow_other : R.string.title_block_other),
                    piOther
            ).build();
            builder.addAction(oAction);

            // Show notification
            if (internet)
                NotificationManagerCompat.from(this).notify(uid, builder.build());
            else {
                NotificationCompat.BigTextStyle expanded = new NotificationCompat.BigTextStyle(builder);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                    expanded.bigText(getString(R.string.msg_installed_n));
                else
                    expanded.bigText(getString(R.string.msg_installed, name));
                expanded.setSummaryText(getString(R.string.title_internet));
                NotificationManagerCompat.from(this).notify(uid, expanded.build());
            }

        } catch (PackageManager.NameNotFoundException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    @Override
    public void onCreate() {
        Log.i(TAG, "Create version=" + Util.getSelfVersionName(this) + "/" + Util.getSelfVersionCode(this));
        startForeground(NOTIFY_WAITING, getWaitingNotification());

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        if (jni_context != 0) {
            Log.w(TAG, "Create with context=" + jni_context);
            jni_stop(jni_context);
            synchronized (jni_lock) {
                jni_done(jni_context);
                jni_context = 0;
            }
        }

        // Native init
        jni_context = jni_init(Build.VERSION.SDK_INT);
        Log.i(TAG, "Created context=" + jni_context);
        boolean pcap = prefs.getBoolean("pcap", false);
        setPcap(pcap, this);

        prefs.registerOnSharedPreferenceChangeListener(this);

        Util.setTheme(this);
        vpnServiceOncreate();

        HandlerThread commandThread = new HandlerThread(getString(R.string.app_name) + " command", Process.THREAD_PRIORITY_FOREGROUND);
        HandlerThread logThread = new HandlerThread(getString(R.string.app_name) + " log", Process.THREAD_PRIORITY_BACKGROUND);
        HandlerThread statsThread = new HandlerThread(getString(R.string.app_name) + " stats", Process.THREAD_PRIORITY_BACKGROUND);
        commandThread.start();
        logThread.start();
        statsThread.start();

        commandLooper = commandThread.getLooper();
        logLooper = logThread.getLooper();
        statsLooper = statsThread.getLooper();

        commandHandler = new CommandHandler(commandLooper);
        logHandler = new LogHandler(logLooper);
        statsHandler = new StatsHandler(statsLooper);

        // Listen for user switches
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            IntentFilter ifUser = new IntentFilter();
            ifUser.addAction(Intent.ACTION_USER_BACKGROUND);
            ifUser.addAction(Intent.ACTION_USER_FOREGROUND);
            registerReceiver(userReceiver, ifUser);
            registeredUser = true;
        }

        // Listen for idle mode state changes
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            IntentFilter ifIdle = new IntentFilter();
            ifIdle.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
            registerReceiver(idleStateReceiver, ifIdle);
            registeredIdleState = true;
        }

        // Listen for added/removed applications
        IntentFilter ifPackage = new IntentFilter();
        ifPackage.addAction(Intent.ACTION_PACKAGE_ADDED);
        ifPackage.addAction(Intent.ACTION_PACKAGE_REMOVED);
        ifPackage.addDataScheme("package");
        registerReceiver(packageChangedReceiver, ifPackage);
        registeredPackageChanged = true;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            try {
                listenNetworkChanges();
            } catch (Throwable ex) {
                Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                listenConnectivityChanges();
            }
        else
            listenConnectivityChanges();

        // Monitor networks
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        cm.registerNetworkCallback(
                new NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
                networkMonitorCallback);

        // Setup house holding
        Intent alarmIntent = new Intent(this, ServiceSinkhole.class);
        alarmIntent.setAction(ACTION_HOUSE_HOLDING);
        PendingIntent pi;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            pi = PendingIntent.getForegroundService(this, 0, alarmIntent, PendingIntent.FLAG_UPDATE_CURRENT);
        else
            pi = PendingIntent.getService(this, 0, alarmIntent, PendingIntent.FLAG_UPDATE_CURRENT);

        AlarmManager am = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
        am.setInexactRepeating(AlarmManager.RTC, SystemClock.elapsedRealtime() + 60 * 1000, AlarmManager.INTERVAL_HALF_DAY, pi);
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        if ("theme".equals(name)) {
            Log.i(TAG, "Theme changed");
            Util.setTheme(this);
            if (state != State.none) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                stopForeground(true);
            }
            if (state == State.enforcing)
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
            else if (state != State.none)
                startForeground(NOTIFY_WAITING, getWaitingNotification());
            Log.d(TAG, "Start foreground state=" + state.toString());
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (state == State.enforcing)
            startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
        else
            startForeground(NOTIFY_WAITING, getWaitingNotification());

        return super.onStartCommand(intent, flags, startId);
    }

    protected void set(Intent intent) {
        super.set(intent);

        // Update notification
        int uid = intent.getIntExtra(EXTRA_UID, 0);
        notifyNewApplication(uid);

        // Update UI
        Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
        LocalBroadcastManager.getInstance(ServiceSinkhole.this).sendBroadcast(ruleset);
    }

    @Override
    public void onRevoke() {
        // Feedback
        showDisabledNotification();
        WidgetMain.updateWidgets(this);

        final Intent i = new Intent();
        i.putExtra(RESTART_BROADCAST,"RESTART_BROADCAST");
        i.setAction(RESTART_BROADCAST);
        i.addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES);
        getApplicationContext().sendBroadcast(i);

        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        synchronized (this) {
            Log.i(TAG, "Destroy");
            commandLooper.quit();
            logLooper.quit();
            statsLooper.quit();

            for (Command command : Command.values())
                commandHandler.removeMessages(command.ordinal());
            releaseLock(this);

            // Registered in command loop
            if (registeredInteractiveState) {
                unregisterReceiver(interactiveStateReceiver);
                registeredInteractiveState = false;
            }
            if (callStateListener != null) {
                TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
                tm.listen(callStateListener, PhoneStateListener.LISTEN_NONE);
                callStateListener = null;
            }

            // Register in onCreate
            if (registeredUser) {
                unregisterReceiver(userReceiver);
                registeredUser = false;
            }
            if (registeredIdleState) {
                unregisterReceiver(idleStateReceiver);
                registeredIdleState = false;
            }
            if (registeredPackageChanged) {
                unregisterReceiver(packageChangedReceiver);
                registeredPackageChanged = false;
            }

            if (networkCallback != null) {
                unlistenNetworkChanges();
                networkCallback = null;
            }
            if (registeredConnectivityChanged) {
                unregisterReceiver(connectivityChangedReceiver);
                registeredConnectivityChanged = false;
            }

            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            cm.unregisterNetworkCallback(networkMonitorCallback);

            if (phone_state) {
                TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
                tm.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE);
                phone_state = false;
            }

            try {
                if (vpn != null) {
                    stopNative(vpn);
                    stopVPN(vpn);
                    vpn = null;
                    unprepare();
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            Log.i(TAG, "Destroy context=" + jni_context);
            synchronized (jni_lock) {
                jni_done(jni_context);
                jni_context = 0;
            }

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.unregisterOnSharedPreferenceChangeListener(this);
        }

        super.vpnServiceOnDestroy();
    }

    @Override
    void runService(String reason, Context context) {
        run(reason, context);
    }

    @Override
    void startService(String reason, Context context) {
        start(reason, context);
    }

    @Override
    void reloadService(String reason, Context context, boolean interactive) {
        reload(reason, context, interactive);
    }

    @Override
    void stopService(String reason, Context context, boolean vpnonly) {
        stop(reason, context, vpnonly);
    }

    private Notification getEnforcingNotification(int allowed, int blocked, int hosts) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "foreground");
        builder.setSmallIcon(isLockedDown(last_metered) ? R.drawable.ic_lock_outline_white_24dp : R.drawable.ic_security_white_24dp)
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            builder.setContentTitle(getString(R.string.msg_started));
        else
            builder.setContentTitle(getString(R.string.app_name))
                    .setContentText(getString(R.string.msg_started));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                    .setPriority(NotificationCompat.PRIORITY_MIN);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setContentText(getString(R.string.msg_packages));
            return builder.build();
        } else {
            NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
            notification.bigText(getString(R.string.msg_started));
            notification.setSummaryText(getString(R.string.msg_packages));
            return notification.build();
        }
    }

    private void updateEnforcingNotification(int allowed, int total) {
        // Update notification
        Notification notification = getEnforcingNotification(allowed, total - allowed, mapHostsBlocked.size());
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTIFY_ENFORCING, notification);
    }

    private Notification getWaitingNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "foreground");
        builder.setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            builder.setContentTitle(getString(R.string.msg_waiting));
        else
            builder.setContentTitle(getString(R.string.app_name))
                    .setContentText(getString(R.string.msg_waiting));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                    .setPriority(NotificationCompat.PRIORITY_MIN);

        return builder.build();
    }

    private void showDisabledNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_revoked))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_revoked));

        NotificationManagerCompat.from(this).notify(NOTIFY_DISABLED, notification.build());
    }

    private void showAutoStartNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        main.putExtra(ActivityMain.EXTRA_APPROVE, true);
        PendingIntent pi = PendingIntent.getActivity(this, NOTIFY_AUTOSTART, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_autostart))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_autostart));

        NotificationManagerCompat.from(this).notify(NOTIFY_AUTOSTART, notification.build());
    }

    private void showErrorNotification(String message) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_error, message))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_error, message));
        notification.setSummaryText(message);

        NotificationManagerCompat.from(this).notify(NOTIFY_ERROR, notification.build());
    }

    private void showAccessNotification(int uid) {
        String name = TextUtils.join(", ", Util.getApplicationNames(uid, ServiceSinkhole.this));

        Intent main = new Intent(ServiceSinkhole.this, ActivityMain.class);
        main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
        PendingIntent pi = PendingIntent.getActivity(ServiceSinkhole.this, uid + 10000, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        int colorOn = tv.data;
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        int colorOff = tv.data;

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "access");
        builder.setSmallIcon(R.drawable.ic_cloud_upload_white_24dp)
                .setGroup("AccessAttempt")
                .setContentIntent(pi)
                .setColor(colorOff)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            builder.setContentTitle(name)
                    .setContentText(getString(R.string.msg_access_n));
        else
            builder.setContentTitle(getString(R.string.app_name))
                    .setContentText(getString(R.string.msg_access, name));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        DateFormat df = new SimpleDateFormat("dd HH:mm");

        NotificationCompat.InboxStyle notification = new NotificationCompat.InboxStyle(builder);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            notification.addLine(getString(R.string.msg_access_n));
        else {
            String sname = getString(R.string.msg_access, name);
            int pos = sname.indexOf(name);
            Spannable sp = new SpannableString(sname);
            sp.setSpan(new StyleSpan(Typeface.BOLD), pos, pos + name.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            notification.addLine(sp);
        }

        long since = 0;
        PackageManager pm = getPackageManager();
        String[] packages = pm.getPackagesForUid(uid);
        if (packages != null && packages.length > 0)
            try {
                since = pm.getPackageInfo(packages[0], 0).firstInstallTime;
            } catch (PackageManager.NameNotFoundException ignored) {
            }

        try (Cursor cursor = DatabaseHelper.getInstance(ServiceSinkhole.this).getAccessUnset(uid, 7, since)) {
            int colDAddr = cursor.getColumnIndex("daddr");
            int colTime = cursor.getColumnIndex("time");
            int colAllowed = cursor.getColumnIndex("allowed");
            while (cursor.moveToNext()) {
                StringBuilder sb = new StringBuilder();
                sb.append(df.format(cursor.getLong(colTime))).append(' ');

                String daddr = cursor.getString(colDAddr);
                if (Util.isNumericAddress(daddr))
                    try {
                        daddr = InetAddress.getByName(daddr).getHostName();
                    } catch (UnknownHostException ignored) {
                    }
                sb.append(daddr);

                int allowed = cursor.getInt(colAllowed);
                if (allowed >= 0) {
                    int pos = sb.indexOf(daddr);
                    Spannable sp = new SpannableString(sb);
                    ForegroundColorSpan fgsp = new ForegroundColorSpan(allowed > 0 ? colorOn : colorOff);
                    sp.setSpan(fgsp, pos, pos + daddr.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                    notification.addLine(sp);
                } else
                    notification.addLine(sb);
            }
        }

        NotificationManagerCompat.from(this).notify(uid + 10000, notification.build());
    }

    private void showUpdateNotification(String name, String url) {
        Intent download = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        PendingIntent pi = PendingIntent.getActivity(this, 0, download, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(name)
                .setContentText(getString(R.string.msg_update))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationManagerCompat.from(this).notify(NOTIFY_UPDATE, builder.build());
    }

    private void removeWarningNotifications() {
        NotificationManagerCompat.from(this).cancel(NOTIFY_DISABLED);
        NotificationManagerCompat.from(this).cancel(NOTIFY_AUTOSTART);
        NotificationManagerCompat.from(this).cancel(NOTIFY_ERROR);
    }

    public static void run(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.run);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void start(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.start);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void reload(String reason, Context context, boolean interactive) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (prefs.getBoolean("enabled", false)) {
            Intent intent = new Intent(context, ServiceSinkhole.class);
            intent.putExtra(EXTRA_COMMAND, Command.reload);
            intent.putExtra(EXTRA_REASON, reason);
            intent.putExtra(EXTRA_INTERACTIVE, interactive);
            ContextCompat.startForegroundService(context, intent);
        }
    }

    public static void stop(String reason, Context context, boolean vpnonly) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.stop);
        intent.putExtra(EXTRA_REASON, reason);
        intent.putExtra(EXTRA_TEMPORARY, vpnonly);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void reloadStats(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.stats);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }
}
