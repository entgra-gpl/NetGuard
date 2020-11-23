package eu.faircode.netguard;

import android.annotation.SuppressLint;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import androidx.annotation.Nullable;

public class AgentCommunicationService extends Service {

    public static final String TAG = "AgentCommunicationService.Service";
    public static final String APPLY_APP_USAGE_POLICY = "eu.faircode.netguard.APPLY_APP_USAGE_POLICY";
    public static final String REMOVE_APP_USAGE_POLICY = "eu.faircode.netguard.REMOVE_APP_USAGE_POLICY";
    public static final String INTENT_EXTRA_OPERATION_PAYLOAD = "payload";
    private volatile boolean mServiceBound = false;
    ServiceSinkhole sinkhole;


    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

//    @Override
//    public void onCreate() {
//        super.onCreate();
//        Intent agentServiceIntent = new Intent(this, AgentForegroundService.class);
//        bindService(agentServiceIntent, mServiceConnection, Context.BIND_AUTO_CREATE);
//    }

    @SuppressLint("LongLogTag")
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);
        if (intent != null && intent.getAction() != null) {
            Log.i(TAG, " Action: " + intent.getAction());
            switch (intent.getAction()) {
                case APPLY_APP_USAGE_POLICY:
//                    ServiceSinkhole.
//                    Intent agentServiceIntent = new Intent(this, AgentForegroundService.class);
//                    bindService(agentServiceIntent, mServiceConnection, Context.BIND_AUTO_CREATE);
                    String  payload = intent.getExtras().getString(INTENT_EXTRA_OPERATION_PAYLOAD);
                    ServiceSinkhole.controlDataOfPackage(this, payload);
                    break;
                case REMOVE_APP_USAGE_POLICY:
                    String  operation = intent.getExtras().getString(INTENT_EXTRA_OPERATION_PAYLOAD);
                    ServiceSinkhole.revokePolicy(this, operation);
                    break;
            }
        }

        return START_STICKY;
    }

    class FirewallServiceConnection implements ServiceConnection {

        String message;
        String command;

        public FirewallServiceConnection(String msg, String command) {
            message = msg;
            this.command = command;
        }

        @SuppressLint("LongLogTag")
        public void onServiceConnected(ComponentName name, IBinder boundService) {

            ServiceSinkhole.LocalBinder localBinder = (ServiceSinkhole.LocalBinder) boundService;
            sinkhole = localBinder.getService();

            Log.d(TAG, "Sending command " + command);
//            try {
//                switch (command) {
//                    case APPLY_APP_USAGE_POLICY:
//                        sinkhole.controlDataOfPackage(message);
//                        break;
//                    case REMOVE_APP_USAGE_POLICY:
//                        sinkhole.revokePolicy(message);
//                        break;
//                }

//                context.unbindService(firewallServiceConnection);
//            } catch (RemoteException e) {
//                Log.e(TAG, "could not bind to service " + e.getMessage());
//            }
        }

        public void onServiceDisconnected(ComponentName name) {
            sinkhole = null;
        }
    }

//    @Override
//    public void onDestroy() {
//        super.onDestroy();
//        if (mServiceBound) {
//            unbindService(mServiceConnection);
//            mServiceBound = false;
//        }
//    }
}
