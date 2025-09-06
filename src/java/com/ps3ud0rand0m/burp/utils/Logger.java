package com.ps3ud0rand0m.burp.utils;

import burp.api.montoya.logging.Logging;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public final class Logger {

    private static final AtomicReference<Logging> BURP = new AtomicReference<>();
    private static volatile boolean disabled;

    private Logger() {}

    public static void initialize(Logging montoyaLogging) {
        BURP.set(montoyaLogging);
        disabled = false;
    }

    public static void logInfo(String msg) {
        write(false, safe(msg));
    }

    public static void logError(String msg) {
        write(true, safe(msg));
    }

    private static void write(boolean error, String line) {
        if (disabled) return;
        Logging l = BURP.get();
        if (l == null) return;
        try {
            if (error) {
                l.logToError(line);
            } else {
                l.logToOutput(line);
            }
        } catch (RuntimeException ignored) {
            disabled = true;
        }
    }

    private static String safe(String s) {
        return Objects.toString(s, "");
    }
}
