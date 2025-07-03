package com.greatdayhr.plugin.securitycheck;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import java.io.File;
import java.util.Objects;

public class SecurityCheck {
    private static final String[] GENY_FILES = {
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd"
    };
    private static final String[] PIPES = {
            "/dev/socket/qemud",
            "/dev/qemu_pipe"
    };
    private static final String[] X86_FILES = {
            "ueventd.android_x86.rc",
            "x86.prop",
            "ueventd.ttVM_x86.rc",
            "init.ttVM_x86.rc",
            "fstab.ttVM_x86",
            "fstab.vbox86",
            "init.vbox86.rc",
            "ueventd.vbox86.rc"
    };
    private static final String[] ANDY_FILES = {
            "fstab.andy",
            "ueventd.andy.rc"
    };
    private static final String[] NOX_FILES = {
            "fstab.nox",
            "init.nox.rc",
            "ueventd.nox.rc"
    };
    private static final String[] BLUE_STACKS_FILES = {
            "/mnt/windows/BstSharedFolder"
    };

    private final Context context;

    public SecurityCheck(Context context) {
        this.context = context;
    }

    public static boolean checkFiles(String[] targets) {
        for (String pipe : targets) {
            File file = new File(pipe);
            if (file.exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean checkEmulatorFiles() {
        return (checkFiles(GENY_FILES)
                || checkFiles(ANDY_FILES)
                || checkFiles(NOX_FILES)
                || checkFiles(X86_FILES)
                || checkFiles(PIPES)
                || checkFiles(BLUE_STACKS_FILES));
    }

    private boolean checkBuildProperties() {
        String[] emulatorIndicators = {
                "generic", "unknown", "emulator", "sdk", "x86", "goldfish", "ranchu", "google_sdk"
        };

        String buildFingerprint = Build.FINGERPRINT.toLowerCase();
        String model = Build.MODEL.toLowerCase();
        String manufacturer = Build.MANUFACTURER.toLowerCase();
        String brand = Build.BRAND.toLowerCase();
        String device = Build.DEVICE.toLowerCase();
        String product = Build.PRODUCT.toLowerCase();
        String hardware = Build.HARDWARE.toLowerCase();

        for (String indicator : emulatorIndicators) {
            if (buildFingerprint.contains(indicator) ||
                model.contains(indicator) ||
                manufacturer.contains(indicator) ||
                brand.contains(indicator) ||
                device.contains(indicator) ||
                product.contains(indicator) ||
                hardware.contains(indicator)) {
                return true;
            }
        }

        return false;
    }

    private boolean checkTelephony() {
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm == null) return true;

            String networkOperator = tm.getNetworkOperatorName();
            String simOperator = tm.getSimOperatorName();

            return (networkOperator == null || networkOperator.isEmpty() || networkOperator.equalsIgnoreCase("android")) ||
                   (simOperator == null || simOperator.isEmpty() || simOperator.equalsIgnoreCase("android"));
        } catch (SecurityException e) {
            // Permission not granted, skip this check
            return false;
        }
    }

    private boolean checkSensorCount() {
        SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
        if (sm == null) return true;

        int sensorCount = sm.getSensorList(Sensor.TYPE_ALL).size();
        return sensorCount < 5; // Real devices typically have more than 5 sensors
    }

    private boolean checkAndroidId() {
        String androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        return androidId == null || androidId.length() < 10;
    }

    public boolean isEmulationDetected() {
        boolean emulatorProps = (
                Build.MANUFACTURER.contains("Genymotion")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.toLowerCase().contains("droid4x")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Objects.equals(Build.HARDWARE, "goldfish")
                || Objects.equals(Build.HARDWARE, "vbox86")
                || Build.HARDWARE.toLowerCase().contains("nox")
                || Build.FINGERPRINT.startsWith("generic")
                || Objects.equals(Build.PRODUCT, "sdk")
                || Objects.equals(Build.PRODUCT, "google_sdk")
                || Objects.equals(Build.PRODUCT, "sdk_x86")
                || Objects.equals(Build.PRODUCT, "vbox86p")
                || Build.PRODUCT.toLowerCase().contains("nox")
                || Build.BOARD.toLowerCase().contains("nox")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
        );

        return emulatorProps
                || checkEmulatorFiles()
                || checkBuildProperties()
                || checkTelephony()
                || checkSensorCount()
                || checkAndroidId();
    }
}
