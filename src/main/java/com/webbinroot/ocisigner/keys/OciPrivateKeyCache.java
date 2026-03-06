package com.webbinroot.ocisigner.keys;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared RSA private key loader + cache for API key and session token flows.
 */
public final class OciPrivateKeyCache {

    private static final class CachedPk {
        final int pemHash;
        final String passHash;
        final PrivateKey pk;
        CachedPk(int pemHash, String passHash, PrivateKey pk) {
            this.pemHash = pemHash;
            this.passHash = passHash;
            this.pk = pk;
        }
    }

    private static final OciKeyLoader KEY_LOADER = new OciKeyLoader();
    private static final ConcurrentHashMap<String, CachedPk> CACHE = new ConcurrentHashMap<>();

    private OciPrivateKeyCache() {}

    /**
     * Load an RSA private key from PEM text or a filesystem path.
     *
     * Example inputs:
     *  - sourceOrPath="/home/kali/.oci/oci_api_key.pem"
     *  - sourceOrPath="-----BEGIN RSA PRIVATE KEY-----..."
     * Example output:
     *  - PrivateKey instance (cached in-memory)
     */
    public static PrivateKey loadRsaPrivateKey(String sourceOrPath, String passphrase) {
        String src = nz(sourceOrPath);
        if (src.isBlank()) throw new IllegalArgumentException("Private key path is missing.");

        String pem;
        byte[] pemBytes;

        if (src.startsWith("pem:") || src.startsWith("pem64:") || src.startsWith("base64:")) {
            String b64 = src.substring(src.indexOf(':') + 1).trim();
            if (b64.isBlank()) {
                throw new IllegalArgumentException("Private key PEM is empty.");
            }
            try {
                pemBytes = java.util.Base64.getDecoder().decode(b64);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Private key PEM is not valid base64.", e);
            }
            pem = new String(pemBytes, StandardCharsets.UTF_8);
        } else if (src.contains("-----BEGIN")) {
            pem = src;
            pemBytes = pem.getBytes(StandardCharsets.UTF_8);
        } else {
            pemBytes = KEY_LOADER.getPrivateKeyPemBytes(src);
            if (pemBytes == null || pemBytes.length == 0) {
                throw new IllegalArgumentException("Unable to read private key: " + src);
            }
            pem = new String(pemBytes, StandardCharsets.UTF_8);
        }

        int pemHash = Arrays.hashCode(pemBytes);
        String passHash = (passphrase == null) ? "" : Integer.toHexString(passphrase.hashCode());
        String cacheKey = pemHash + "|" + passHash;

        CachedPk ck = CACHE.get(cacheKey);
        if (ck != null && ck.pemHash == pemHash && ck.passHash.equals(passHash)) {
            return ck.pk;
        }

        PrivateKey pk = OciX509Suppliers.loadRsaPrivateKey(pem, passphrase);
        CACHE.put(cacheKey, new CachedPk(pemHash, passHash, pk));
        return pk;
    }

    /**
     * Clear cached private keys (no disk side-effects).
     */
    public static void clear() {
        CACHE.clear();
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }
}
