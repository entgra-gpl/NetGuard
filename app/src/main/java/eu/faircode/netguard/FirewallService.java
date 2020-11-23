package eu.faircode.netguard;

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class FirewallService extends Service {

    private static final String TAG = FirewallService.class.getName();

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private final IFirewall.Stub mBinder = new IFirewall.Stub() {

        @Override
        public void controlDataOfPackage(String aString) throws RemoteException {
            try {
                JSONArray apps = new JSONArray(aString);
                for (int i = 0; i < apps.length(); i++) {
                    JSONObject app = apps.getJSONObject(i);
                    String packageName = app.getString("packageName");
                    boolean isWiFiOff = app.getBoolean("isWifiOff");
                    boolean isMobileOff = app.getBoolean("isMobileOff");
                    changeDataState(packageName, isWiFiOff, isMobileOff);
                }
                ServiceSinkhole.reload("ui", FirewallService.this, false);
            } catch (JSONException e) {
                Log.e(TAG, "Could not parse VPN firewall rules");
            }
        }

        @Override
        public void revokePolicy(String aString) throws RemoteException {
            try {
                JSONArray apps = new JSONArray(aString);
                for (int i = 0; i < apps.length(); i++) {
                    changeDataState(apps.getString(i), false, false);
                }
                ServiceSinkhole.reload("ui", FirewallService.this, false);
            } catch (JSONException e) {
                Log.e(TAG, "Could not parse VPN firewall rules");
            }
        }

        @Override
        public void start() throws RemoteException {
                ServiceSinkhole.start("ui", FirewallService.this);
        }
    };

    private void hideApp() {
        PackageManager p = getPackageManager();
        ComponentName componentName = new ComponentName(this, ActivityMain.class);
        p.setComponentEnabledSetting(componentName,PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
    }

    private void changeDataState(String packageName, boolean offWiFi, boolean offMobileData) {
        SharedPreferences wifi = this.getSharedPreferences("wifi", Context.MODE_PRIVATE);
        SharedPreferences other = this.getSharedPreferences("other", Context.MODE_PRIVATE);

        wifi.edit().putBoolean(packageName, offWiFi).apply();
        other.edit().putBoolean(packageName, offMobileData).apply();
    }



}