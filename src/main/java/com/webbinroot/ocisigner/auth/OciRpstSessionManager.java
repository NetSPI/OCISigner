package com.webbinroot.ocisigner.auth;

import com.webbinroot.ocisigner.keys.OciPrivateKeyCache;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.util.OciTokenUtils;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Resource Principal session token helper (explicit RPST + private key).
 *
 * - Reads token from file path or raw token string.
 * - Reads private key from file path or inline PEM.
 * - Caches token + key for signing.
 */
public final class OciRpstSessionManager {
    private static final ConcurrentHashMap<String, OciX509SessionManager.SessionInfo> CACHE = new ConcurrentHashMap<>();
    private static final long REFRESH_SKEW_SEC = 120;

    private OciRpstSessionManager() {}

    /**
     * True if RPST + private key inputs are present.
     */
    public static boolean hasExplicitInputs(Profile p) {
        if (p == null) return false;
        return !isBlank(p.resourcePrincipalRpst) && !isBlank(p.resourcePrincipalPrivateKey);
    }

    /**
     * Return cached RPST session info or refresh if needed.
     * Example output: SessionInfo(token="<RPST>", expEpochSec=...)
     */
    public static OciX509SessionManager.SessionInfo getOrRefresh(Profile p,
                                                                 Consumer<String> infoLog,
                                                                 Consumer<String> errorLog,
                                                                 boolean forceRefresh) {
        Objects.requireNonNull(p, "profile");
        String key = cacheKey(p);
        OciX509SessionManager.SessionInfo existing = CACHE.get(key);
        if (!forceRefresh && existing != null && !isExpiredSoon(existing)) {
            return existing;
        }
        OciX509SessionManager.SessionInfo refreshed = refresh(p, infoLog, errorLog);
        if (refreshed != null) {
            CACHE.put(key, refreshed);
        }
        return refreshed;
    }

    /**
     * Force-refresh RPST session info from token + private key.
     * Example output: SessionInfo(token="<RPST>", expEpochSec=...)
     */
    public static OciX509SessionManager.SessionInfo refresh(Profile p,
                                                            Consumer<String> infoLog,
                                                            Consumer<String> errorLog) {
        Objects.requireNonNull(p, "profile");
        try {
            String token = OciTokenUtils.resolveTokenValue(nz(p.resourcePrincipalRpst));
            if (token.isBlank()) {
                throw new IllegalArgumentException("RPST token is empty.");
            }

            String pass = nz(p.resourcePrincipalPrivateKeyPassphrase);
            if (pass.isBlank()) pass = null;

            PrivateKey pk = OciPrivateKeyCache.loadRsaPrivateKey(nz(p.resourcePrincipalPrivateKey), pass);
            if (pk == null) {
                throw new IllegalArgumentException("Unable to load resource principal private key.");
            }

            long exp = OciTokenUtils.extractJwtExp(token);
            if (exp <= 0) {
                exp = Instant.now().getEpochSecond() + 300;
            }

            OciX509SessionManager.SessionInfo info =
                    new OciX509SessionManager.SessionInfo(
                            token,
                            exp,
                            pk,
                            null,
                            Instant.now().getEpochSecond()
                    );

            if (infoLog != null) {
                infoLog.accept("[OCI Signer][RP] RPST loaded; exp=" + exp);
            }
            return info;
        } catch (Exception e) {
            if (errorLog != null) errorLog.accept("[OCI Signer][RP] Failed loading RPST: " + e.getMessage());
            if (infoLog != null) infoLog.accept("[OCI Signer][RP] Failed loading RPST: " + e.getMessage());
            return null;
        }
    }

    private static boolean isExpiredSoon(OciX509SessionManager.SessionInfo info) {
        if (info == null) return true;
        long now = Instant.now().getEpochSecond();
        return (info.expEpochSec - now) <= REFRESH_SKEW_SEC;
    }

    private static String cacheKey(Profile p) {
        return "RP|" + cachePart(p.resourcePrincipalRpst) + "|" + cachePart(p.resourcePrincipalPrivateKey);
    }

    private static String cachePart(String s) {
        String v = nz(s);
        if (v.isBlank()) return "";
        return "hash:" + Integer.toHexString(v.hashCode()) + ":" + v.length();
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }
}
