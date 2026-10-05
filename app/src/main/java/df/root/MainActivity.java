package df.root;

import android.content.ComponentName;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import df.root.databinding.ActivityMainBinding;

import java.io.File;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    private ActivityMainBinding binding;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private final Executor mCmd = Executors.newSingleThreadExecutor();
    // KURAL bekcisi: load sadece pencere acikken (panic/Odin korumasi).
    public static volatile boolean foreground = false;
    private PowerManager.WakeLock mBootWl;

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        mMain.post(() -> {
            binding.outputView.append(msg);
            binding.outputScroll.post(() -> binding.outputScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        foreground = true;
    }

    @Override
    protected void onPause() {
        foreground = false;
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (mBootWl != null) {
            try { mBootWl.release(); } catch (Exception ignored) {}
            mBootWl = null;
        }
        super.onDestroy();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        setSupportActionBar(binding.toolbar);
        // Baslik koddan (layout onbelleklerine karsi garanti):
        // "DFRoot for S21" + baz firmware kucuk puntoyla.
        if (getSupportActionBar() != null) {
            android.text.SpannableStringBuilder sb =
                    new android.text.SpannableStringBuilder("DFRoot for S21  ");
            int start = sb.length();
            sb.append("(G991BXXSJHZC2)");
            sb.setSpan(new android.text.style.RelativeSizeSpan(0.6f),
                    start, sb.length(),
                    android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            sb.setSpan(new android.text.style.StyleSpan(android.graphics.Typeface.ITALIC),
                    start, sb.length(),
                    android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            getSupportActionBar().setTitle(sb);
            getSupportActionBar().setSubtitle("(@diabl0w github/xda)");
        }

        // o1s v57+: same-boot reruns allowed (worker unlinks stale
        // markers at start and re-arms atomically). Never gate on /dev/df.
        binding.btnRun.setEnabled(true);

        binding.btnRun.setOnClickListener(v -> {
            binding.btnRun.setEnabled(false);
            binding.outputView.setText("");
            boolean softReboot = binding.switchManualSoftReboot.isChecked();
            mExec.execute(() -> runExploit(softReboot));
        });

        binding.btnKsu.setOnClickListener(v -> {
            binding.btnKsu.setEnabled(false);
            mCmd.execute(() -> {
                try {
                    ExploitRunner.loadKsu(this, this);
                } catch (Exception e) {
                    report("loadKsu FAILED: " + e + "\n");
                } finally {
                    mMain.post(() -> binding.btnKsu.setEnabled(true));
                }
            });
        });

        binding.btnShell.setOnClickListener(v -> {
            String cmd = binding.shellInput.getText().toString().trim();
            if (cmd.isEmpty()) return;
            mCmd.execute(() -> ExploitRunner.sudShell(this, cmd));
        });

        ComponentName bootReceiver = new ComponentName(this, BootReceiver.class);
        int state = getPackageManager().getComponentEnabledSetting(bootReceiver);
        boolean bootEnabled = state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
        binding.switchBootStart.setChecked(bootEnabled);
        binding.switchBootStart.setOnCheckedChangeListener((btn, checked) -> {
            getPackageManager().setComponentEnabledSetting(bootReceiver,
                checked ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            binding.switchAutoSoftReboot.setEnabled(checked);
        });

        boolean autoSoftReboot = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", true);
        binding.switchAutoSoftReboot.setChecked(autoSoftReboot);
        binding.switchAutoSoftReboot.setEnabled(bootEnabled);
        binding.switchAutoSoftReboot.setOnCheckedChangeListener((btn, checked) ->
            createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("auto_soft_reboot", checked).apply());

        // Bildirim izni (Android 13+): boot bildirimi icin sart.
        // Manuel acilista istenir (boot'ta sorulamaz).
        if (Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[]{ android.Manifest.permission.POST_NOTIFICATIONS }, 0xB00);
        }

        // Boot zinciri: bildirimden/otomatik gelen activity pencereyi acik
        // tutar, exploit+load'u kendisi kosar. Arka planda ASLA load yok.
        if (getIntent() != null && getIntent().getBooleanExtra(BootReceiver.EXTRA_AUTOBOOT, false)) {
            if (Build.VERSION.SDK_INT >= 27) {
                setShowWhenLocked(true);
                setTurnScreenOn(true);
            }
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            mBootWl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "dfroot:autoboot");
            mBootWl.acquire(10 * 60 * 1000L);
            report("=== autoboot: window open, starting ===\n");
            binding.btnRun.setEnabled(false);
            binding.btnKsu.setEnabled(false);
            binding.outputView.setText("");
            boolean softReboot = createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .getBoolean("auto_soft_reboot", true);
            mExec.execute(() -> runExploitAuto(softReboot));
        }
    }

    private void runExploitAuto(boolean softReboot) {
        // Manuel akisla ayni paralellik: exploit (300sn pencere
        // beklemeli) arka planda kosarken /dev/df gorunur gorunmez
        // load yapilir. fastMode serve'i kapatir, o yuzde false.
        final int[] rcBox = new int[]{ -1 };
        Thread exploit = new Thread(() -> {
            try {
                rcBox[0] = ExploitRunner.run(this, this, softReboot, false);
            } catch (Exception e) {
                Log.e(TAG, "autoboot exploit exception", e);
                report("\nautoboot exploit exception: " + e + "\n");
            } finally {
                mMain.post(() -> binding.btnRun.setEnabled(true));
            }
        }, "dfroot-auto-exploit");
        exploit.start();
        // onCreate onResume'dan once kosar; once pencerenin
        // gercekten one cikmasini bekle (yoksa bekci doner).
        for (int i = 0; i < 30 && !foreground; i++) {
            try { Thread.sleep(1000); } catch (InterruptedException ie) { break; }
        }
        boolean ready = false;
        for (int i = 0; i < 180 && foreground; i++) {
            if (new java.io.File("/dev/df").exists()) { ready = true; break; }
            try { Thread.sleep(1000); } catch (InterruptedException ie) { break; }
        }
        if (!ready) {
            report("autoboot: exploit FAILED (no /dev/df in 180s, rc=" + rcBox[0] + ")\n");
            mMain.post(() ->
                Toast.makeText(this, "Autoboot: exploit failed", Toast.LENGTH_LONG).show());
            return;
        }
        if (!foreground) {
            report("autoboot: window closed mid-run, LOAD ABORTED (panic guard)\n");
            return;
        }
        // SUCCESS sonrasi 2sn: auto-ladder probe donsun, sonra load.
        try { Thread.sleep(2000); } catch (InterruptedException ie) { return; }
        if (!foreground) {
            report("autoboot: window closed during settle, LOAD ABORTED (panic guard)\n");
            return;
        }
        report("autoboot: exploit ok, loading KernelSU (window open)\n");
        try {
            ExploitRunner.loadKsu(this, this);
            report("autoboot: DONE\n");
            BootReceiver.cancelBootNotification(this);
        } catch (Exception e) {
            report("autoboot loadKsu FAILED: " + e + "\n");
        } finally {
            mMain.post(() -> binding.btnKsu.setEnabled(true));
        }
    }

    private void runExploit(boolean softReboot) {
        try {
            int rc = ExploitRunner.run(this, this, softReboot, false);
            String msg = rc == 0 ? "DFRoot: SUCCESS"
                       : rc == 1 ? "DFRoot FAILED: ksud exited with error"
                       : rc == 2 ? "DFRoot FAILED: check logs"
                       : "DFRoot FAILED: failed to patch files";
            String sudrc = ExploitRunner.readSudrc();
            if (sudrc != null) report("sudrc(exec errno): " + sudrc + "\n");
            mMain.post(() -> Toast.makeText(this, msg, Toast.LENGTH_LONG).show());
        } catch (Exception e) {
            Log.e(TAG, "exploit exception", e);
            report("\nexception: " + e + "\n");
        } finally {
            mMain.post(() -> binding.btnRun.setEnabled(true));
        }
    }
}
