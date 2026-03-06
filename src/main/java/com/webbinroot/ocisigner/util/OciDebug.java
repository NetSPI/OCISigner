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
     * Emit an error log (always shown).
     */
    public static void error(String msg) { // Error-level log.
        log(msg); // Delegate to base logger.
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
     * Emit a debug log (DEBUG level only).
     */
    public static void debug(String msg) { // Debug-level log.
        if (level == Level.DEBUG) { // Only if DEBUG.
            log(msg); // Emit message.
        }
    }

    /**
     * Emit a single-line message with exception class/message.
     * Example output: "Failed :: IllegalArgumentException: ..."
     */
    public static void log(String msg, Throwable t) { // Log with exception summary.
        log(msg + " :: " + t.getClass().getSimpleName() + ": " + t.getMessage()); // Append exception info.
    }

    /**
     * Emit a compact stack trace (bounded length).
     */
    public static void logStack(String msg, Throwable t) { // Log with bounded stack trace.
        if (t == null) { // If no exception provided,
            log(msg); // Log message only.
            return; // Exit.
        }
        log(msg + " :: " + t.getClass().getSimpleName() + ": " + t.getMessage()); // Log summary.
        StackTraceElement[] st = t.getStackTrace(); // Get stack frames.
        int max = Math.min(st.length, 80); // Cap frames to avoid spam.
        for (int i = 0; i < max; i++) { // Iterate frames.
            log("    at " + st[i]); // Log each frame.
        }
        Throwable cause = t.getCause(); // Check nested cause.
        if (cause != null && cause != t) { // Only if a different cause exists.
            log("Caused by: " + cause.getClass().getSimpleName() + ": " + cause.getMessage()); // Log cause summary.
            StackTraceElement[] st2 = cause.getStackTrace(); // Cause stack.
            int max2 = Math.min(st2.length, 40); // Cap cause frames.
            for (int i = 0; i < max2; i++) { // Iterate cause frames.
                log("    at " + st2[i]); // Log each cause frame.
            }
        }
    }
}
