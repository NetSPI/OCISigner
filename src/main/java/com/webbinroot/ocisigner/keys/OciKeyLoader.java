package com.webbinroot.ocisigner.keys;

import com.webbinroot.ocisigner.util.OciDebug;
import java.io.IOException;
import java.nio.file.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lightweight key file cache (PEM bytes).
 *
 * Purpose:
 *  - Avoid disk reads on every request (prevents UI freezes / CPU spikes).
 *  - Cache is in-memory only (cleared when Burp closes / extension unloads).
 */
public final class OciKeyLoader {

    private static final class CachedKey {
        final long lastModified;
        final byte[] bytes;

        CachedKey(long lastModified, byte[] bytes) {
            this.lastModified = lastModified;
            this.bytes = bytes;
        }
    }

    private final ConcurrentHashMap<String, CachedKey> cache = new ConcurrentHashMap<>();

    /**
     * Read PEM bytes from disk with simple mtime-based caching.
     *
     * Example input:
     *  - "/home/kali/.oci/oci_api_key.pem"
     * Example output:
     *  - byte[] of PEM contents (or null if missing/unreadable)
     */
    public byte[] getPrivateKeyPemBytes(String keyPath) {
        if (keyPath == null || keyPath.trim().isEmpty()) return null;
        String p = keyPath.trim();

        try {
            Path path = Path.of(p);
            if (!Files.exists(path)) {
                OciDebug.debug("[OCI Signer][KeyLoader] Key path not found: " + p);
                return null;
            }

            long lm = Files.getLastModifiedTime(path).toMillis();
            CachedKey ck = cache.get(p);
            if (ck != null && ck.lastModified == lm) {
                OciDebug.debug("[OCI Signer][KeyLoader] Cache hit: " + p + " (bytes=" + ck.bytes.length + ")");
                return ck.bytes;
            }

            byte[] bytes = Files.readAllBytes(path);
            OciDebug.debug("[OCI Signer][KeyLoader] Read key file: " + p + " (bytes=" + bytes.length + ")");
            cache.put(p, new CachedKey(lm, bytes));
            return bytes;

        } catch (IOException | InvalidPathException e) {
            OciDebug.logStack("[OCI Signer][KeyLoader] Failed reading key: " + p, e);
            return null;
        }
    }

    /**
     * Clear in-memory key cache (no disk side-effects).
     */
    public void clear() {
        cache.clear();
    }
}
