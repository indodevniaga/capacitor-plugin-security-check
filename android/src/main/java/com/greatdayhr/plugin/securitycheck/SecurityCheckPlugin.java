package com.greatdayhr.plugin.securitycheck;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "SecurityCheck")
public class SecurityCheckPlugin extends Plugin {

    private SecurityCheck implementation;

    @Override
    public void load() {
        // Inisialisasi dengan context saat plugin dimuat
        implementation = new SecurityCheck(getContext());
    }

    @PluginMethod
    public void isEmulationDetected(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("value", implementation.isEmulationDetected());
        call.resolve(ret);
    }
}

