package df.root;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.PowerManager;
import android.util.Log;

import java.io.File;

public class BootReceiver extends BroadcastReceiver implements IReporter {
    private static final String TAG = "dfroot";
    public static final String EXTRA_AUTOBOOT = "df.root.AUTOBOOT";
    private static final String CHANNEL_ID = "dfroot_boot";
    private static final int NOTIF_ID = 0xDF00;

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (new File("/dev/df").exists()) {
            Log.i(TAG, "boot: already hooked, skipping");
            return;
        }
        Log.i(TAG, "boot: " + intent.getAction());
        // KURAL: exploit de load da pencere acikken yapilir.
        // Arka planda load = panic/Odin riski. Bu yuzden burada
        // SADECE bildirim + tam-ekran activity; is activity'de olur.
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "dfroot:boot");
        wl.acquire(60 * 1000L);
        try {
            NotificationManager nm =
                    (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "DFRoot boot", NotificationManager.IMPORTANCE_HIGH);
            nm.createNotificationChannel(ch);

            Intent act = new Intent(context, MainActivity.class);
            act.putExtra(EXTRA_AUTOBOOT, true);
            act.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                    | Intent.FLAG_ACTIVITY_CLEAR_TOP
                    | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            PendingIntent pi = PendingIntent.getActivity(
                    context, 1, act,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

            Notification notif = new Notification.Builder(context, CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.stat_sys_warning)
                    .setContentTitle("DFRoot: root required")
                    .setContentText("Tap: run exploit + load KernelSU")
                    .setContentIntent(pi)
                    .setFullScreenIntent(pi, true)
                    .setAutoCancel(true)
                    .setOngoing(false)
                    .build();
            nm.notify(NOTIF_ID, notif);
            Log.i(TAG, "boot: notification posted");
        } catch (Exception e) {
            Log.e(TAG, "boot: notify exception", e);
        } finally {
            wl.release();
        }
    }

    public static void cancelBootNotification(Context context) {
        try {
            NotificationManager nm =
                    (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            nm.cancel(NOTIF_ID);
        } catch (Exception ignored) {}
    }
}
