package com.greatdayhr.plugin.securitycheck;

import android.os.Build;
import android.util.Log;

import java.util.Objects;
import java.io.File;

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
                || checkFiles(PIPES));
    }

    public Boolean isEmulationDetected() {
        Boolean emulator = (Build.MANUFACTURER.contains("Genymotion")
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
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")));
        return emulator || checkEmulatorFiles();
    }
    
}
