package com.webbinroot.ocisigner.util; // Package declaration for OCISigner utilities.

import java.util.function.Consumer; // Import functional interface used for logging.

/**
 * Central debug logger for crypto/signing path.
 *
 * - Default logs to stdout.
 * - OciSignerExtension should call: OciDebug.setLogger(api.logging()::logToOutput)
 *   so you get everything in Burp's Output tab.
 */
public final class OciDebug { // Utility class (static-only logger).

    private static volatile Consumer<String> logger = System.out::println; // Where logs are sent (default stdout).
    private static volatile Level level = Level.ERROR; // Current log level (default ERROR only).

    public enum Level { // Supported log levels.
        ERROR, // Always shown.
        INFO,  // Shown in INFO or DEBUG modes.
        DEBUG  // Only shown in DEBUG mode.
    }

    private OciDebug() {} // Prevent instantiation.

    /**
     * Replace the logger sink.
     * Example input: api.logging()::logToOutput
     */
    public static void setLogger(Consumer<String> logFn) { // Setter for log sink.
        if (logFn != null) logger = logFn; // Only replace if non-null.
    }

    /**
     * Set log level by string.
     * Example input: "Debug" -> Level.DEBUG
     */
    public static void setLevel(String lvl) { // Setter for log level from string.
        if (lvl == null) { // If null, default to ERROR.
            level = Level.ERROR; // Default to ERROR.
            return; // Exit early.
        }
        String v = lvl.trim().toUpperCase(); // Normalize input to enum form.
        try { // Parse to enum.
            level = Level.valueOf(v); // Convert string to Level.
        } catch (Exception ignored) { // If invalid, fall back.
            level = Level.ERROR; // Default to ERROR on invalid input.
        }
    }

    /**
     * Emit a raw log line (no level filtering).
     * Example output: "[OCI Signer] ... "
     */
    public static void log(String msg) { // Base log method (unfiltered).
        try { // Guard against logging failures.
            logger.accept(msg); // Emit message.
        } catch (Throwable ignored) { // Never let logging crash Burp.
            // never let logging crash Burp
        }
    }

    /**
     * Emit an info log (INFO/DEBUG levels).
     */
    public static void info(String msg) { // Info-level log.
        if (level == Level.INFO || level == Level.DEBUG) { // Only if INFO or DEBUG.
            log(msg); // Emit message.
        }
    }

    /**
     * True if DEBUG-level logging is active. Lets callers skip building expensive
     * debug-only diagnostics (reflection, network lookups) when nothing will read them.
     */
    public static boolean isDebugEnabled() {
        return level == Level.DEBUG;
    }

    /**
     * Emit a debug log (DEBUG level only).
     */
    public static void debug(String msg) { // Debug-level log.
        if (level == Level.DEBUG) { // Only if DEBUG.
            log(msg); // Emit message.
        }
    }

    /**
     * Emit a message to a caller-supplied sink (unlike log()/info()/debug() above,
     * which always go through the single global logger). Used by auth/signing flow
     * methods that accept their own infoLog/errorLog callbacks, e.g. to route into a
     * specific UI text area rather than the global sink.
     */
    public static void logTo(Consumer<String> log, String msg) {
        if (log != null && msg != null) log.accept(msg);
    }

    /**
     * Emit an error to both a caller-supplied error sink and info sink (same
     * caller-supplied-sink model as logTo() above), appending a compact exception
     * summary when one is provided.
     */
    public static void logErrorTo(Consumer<String> errorLog, Consumer<String> infoLog, String msg, Throwable t) {
        String detail = (t == null) ? "" : (" :: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        if (errorLog != null) errorLog.accept(msg + detail);
        if (infoLog != null) infoLog.accept(msg + detail);
    }

    /**
     * Emit a compact stack trace (bounded length).
     */
    public static void logStack(String msg, Throwable t) { // Log with bounded stack trace.
        logStackTo(OciDebug::log, msg, t);
    }

    /**
     * Same bounded stack-trace dump as logStack(), but to a caller-supplied sink
     * (same caller-supplied-sink model as logTo()/logErrorTo() above) instead of
     * the global logger.
     */
    public static void logStackTo(Consumer<String> log, String msg, Throwable t) {
        if (log == null) return;
        if (t == null) {
            log.accept(msg);
            return;
        }
        log.accept(msg + " :: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        StackTraceElement[] st = t.getStackTrace();
        int max = Math.min(st.length, 80);
        for (int i = 0; i < max; i++) {
            log.accept("    at " + st[i]);
        }
        Throwable cause = t.getCause();
        if (cause != null && cause != t) {
            log.accept("Caused by: " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
            StackTraceElement[] st2 = cause.getStackTrace();
            int max2 = Math.min(st2.length, 40);
            for (int i = 0; i < max2; i++) {
                log.accept("    at " + st2[i]);
            }
        }
    }
}
