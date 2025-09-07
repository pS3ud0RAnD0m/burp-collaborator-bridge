package com.ps3ud0rand0m.burp.utils;

import burp.api.montoya.logging.Logging;

import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thin wrapper over Burp's Montoya Logging with pluggable sinks
 * so UI components (e.g., LogPanel) can mirror the same output.
 */
public final class Logger {

    /** Simple sink contract; implementations must not call back into Logger to avoid loops. */
    public interface Sink {
        void info(String msg);
        void error(String msg);
    }

    private static final AtomicReference<Logging> BURP = new AtomicReference<>();
    private static final CopyOnWriteArrayList<Sink> SINKS = new CopyOnWriteArrayList<>();
    private static volatile boolean disabled;

    private Logger() {}

    public static void initialize(Logging montoyaLogging) {
        BURP.set(montoyaLogging);
        disabled = false;
    }

    public static void addSink(Sink sink) {
        if (sink != null) {
            SINKS.addIfAbsent(sink);
        }
    }

    public static void removeSink(Sink sink) {
        if (sink != null) {
            SINKS.remove(sink);
        }
    }

    public static void logInfo(String msg) {
        write(false, safe(msg));
    }

    public static void logError(String msg) {
        write(true, safe(msg));
    }

    private static void write(boolean error, String line) {
        // 1) Burp console
        if (!disabled) {
            Logging l = BURP.get();
            if (l != null) {
                try {
                    if (error) {
                        l.logToError(line);
                    } else {
                        l.logToOutput(line);
                    }
                } catch (RuntimeException ignored) {
                    disabled = true; // fail closed for Burp logging only
                }
            }
        }
        // 2) Any attached UI sinks (never disable on sink exceptions)
        for (Sink s : SINKS) {
            try {
                if (error) s.error(line);
                else s.info(line);
            } catch (RuntimeException ignored) {
                // ignore faulty sinks
            }
        }
    }

    private static String safe(String s) {
        return Objects.toString(s, "");
    }
}
