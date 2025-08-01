package com.greatdayhr.plugin.securitycheck;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

public class SecurityCheck {

  private final Context context;

  public SecurityCheck(Context context) {
    this.context = context;
  }

  // Emulator indicators (paths)
  private static final String[] EMULATOR_FILES = {
    "/dev/socket/genyd",
    "/dev/socket/baseband_genyd",
    "/dev/socket/qemud",
    "/dev/qemu_pipe",
    "/mnt/windows/BstSharedFolder",
    "ueventd.android_x86.rc",
    "x86.prop",
    "ueventd.ttVM_x86.rc",
    "init.ttVM_x86.rc",
    "fstab.ttVM_x86",
    "fstab.vbox86",
    "init.vbox86.rc",
    "ueventd.vbox86.rc",
    "fstab.andy",
    "ueventd.andy.rc",
    "fstab.nox",
    "init.nox.rc",
    "ueventd.nox.rc"
  };

  private boolean checkEmulatorFiles() {
    for (String path : EMULATOR_FILES) {
      File file = new File(path);
      if (file.exists()) {
        return true;
      }
    }
    return false;
  }

  private boolean checkBuildProperties() {
    String[] indicators = { "generic", "unknown", "emulator", "sdk", "x86", "x86_64", "goldfish", "ranchu", "google_sdk" };

    String[] props = {
      Build.FINGERPRINT,
      Build.MODEL,
      Build.MANUFACTURER,
      Build.BRAND,
      Build.DEVICE,
      Build.PRODUCT,
      Build.HARDWARE,
      Build.BOARD
    };

    for (String prop : props) {
      String lowerProp = prop != null ? prop.toLowerCase() : "";
      for (String indicator : indicators) {
        if (lowerProp.contains(indicator)) {
          return true;
        }
      }
    }

    // Extra checks
    return (Build.BRAND != null && Build.BRAND.startsWith("generic") && Build.DEVICE != null && Build.DEVICE.startsWith("generic"));
  }

  private boolean checkTelephony() {
    try {
      PackageManager pm = context.getPackageManager();
      boolean hasTelephony = pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY);

      if (!hasTelephony) {
        return false; // Misal tablet Wi-Fi only
      }

      TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
      if (tm == null) {
        return false; // Jangan curigai kalau hanya null
      }

      String network = tm.getNetworkOperatorName();
      String sim = tm.getSimOperatorName();

      boolean bothEmpty = (network == null || network.trim().isEmpty()) && (sim == null || sim.trim().isEmpty());

      boolean namedAndroid =
        (network != null && network.equalsIgnoreCase("android")) || (sim != null && sim.equalsIgnoreCase("android"));

      if (namedAndroid) return true;

      return false;
    } catch (SecurityException e) {
      return false;
    }
  }

  private boolean checkSensorCount() {
    SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
    if (sm == null) return true;

    int count = sm.getSensorList(Sensor.TYPE_ALL).size();

    // Emulator hampir selalu memiliki 0–1 sensor
    if (count == 0) return true;

    // Device nyata Android 7 ke bawah, jangan disalahkan
    if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.N_MR1) return false;

    // Device modern seharusnya punya minimal 2 sensor
    return count < 2;
  }

  private boolean checkAndroidId() {
    String androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
    return androidId == null || androidId.length() < 10;
  }

  private boolean isProbablyRunningOnEmulatorCpu() {
    String arch = System.getProperty("os.arch");
    return arch != null && (arch.contains("x86") || arch.contains("86_64"));
  }

  private boolean checkQemuProps() {
    return "1".equals(getSystemProperty("ro.kernel.qemu")) || "1".equals(getSystemProperty("ro.boot.qemu"));
  }

  private String getSystemProperty(String name) {
    try {
      Process process = Runtime.getRuntime().exec("getprop " + name);
      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      String result = reader.readLine();
      reader.close();
      return result != null ? result.trim() : "";
    } catch (Exception e) {
      return "";
    }
  }

  public boolean isEmulationDetected() {
    return (
      checkBuildProperties() ||
        checkEmulatorFiles() ||
        checkTelephony() ||
        checkSensorCount() ||
        checkAndroidId() ||
        isProbablyRunningOnEmulatorCpu() ||
        checkQemuProps()
    );
  }
}
