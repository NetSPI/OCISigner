package com.webbinroot.ocisigner.auth;

import com.oracle.bmc.ConfigFileReader;
import com.webbinroot.ocisigner.keys.OciPrivateKeyCache;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.util.OciTokenUtils;

import java.security.PrivateKey;
import java.util.function.Consumer;

/**
 * Shared resolver for session-token material (token + private key).
 *
 * Centralizes logic used by manual session-token signing for:
 *  - Instance Principal (X.509 federation)
 *  - Resource Principal (RPST)
 *  - Security Token (session token)
 *  - Config Profile (security_token_file)
 */
public final class OciSessionTokenResolver {

    public static final class Material {
        public final String token;
        public final PrivateKey privateKey;

        public Material(String token, PrivateKey privateKey) {
            // Example output: token="<JWT>", privateKey=<RSA key>
            this.token = token;
            this.privateKey = privateKey;
        }
    }

    private OciSessionTokenResolver() {}

    public static Material fromInstancePrincipal(Profile p,
                                                 Consumer<String> infoLog,
                                                 Consumer<String> errorLog,
                                                 boolean forceRefresh) {
        // Example output: Material(token="<JWT>", privateKey=<session key>)
        if (!OciX509SessionManager.hasInstanceX509Inputs(p)) {
            logError(errorLog, infoLog,
                    "[OCI Signer] Manual signing for Instance Principal requires X.509 inputs.",
                    null);
            return null;
        }
        if (!forceRefresh) {
            String provided = nz(p.cachedSessionToken);
            if (!provided.isBlank()) {
                OciX509SessionManager.SessionInfo cached = OciX509SessionManager.peek(p);
                if (cached == null || cached.sessionPrivateKey == null) {
                    logError(errorLog, infoLog,
                            "[OCI Signer] Session token provided but no cached session private key is available.",
                            null);
                    return null;
                }
                String token = OciTokenUtils.resolveTokenValue(provided);
                if (token == null || token.isBlank()) {
                    logError(errorLog, infoLog, "[OCI Signer] Session token is missing.", null);
                    return null;
                }
                return new Material(token, cached.sessionPrivateKey);
            }
        }
        OciX509SessionManager.SessionInfo session =
                OciX509SessionManager.getOrRefresh(p, infoLog, errorLog, forceRefresh);
        if (session == null || session.token == null || session.sessionPrivateKey == null) {
            logError(errorLog, infoLog, "[OCI Signer] Session token unavailable (refresh failed)", null);
            return null;
        }
        return new Material(session.token, session.sessionPrivateKey);
    }

    public static Material fromResourcePrincipal(Profile p,
                                                 Consumer<String> infoLog,
                                                 Consumer<String> errorLog,
                                                 boolean forceRefresh) {
        // Example output: Material(token="<RPST>", privateKey=<session key>)
        if (!OciRpstSessionManager.hasExplicitInputs(p)) {
            logError(errorLog, infoLog,
                    "[OCI Signer] Manual signing for Resource Principal requires RPST + key inputs.",
                    null);
            return null;
        }
        OciX509SessionManager.SessionInfo session =
                OciRpstSessionManager.getOrRefresh(p, infoLog, errorLog, forceRefresh);
        if (session == null || session.token == null || session.sessionPrivateKey == null) {
            logError(errorLog, infoLog, "[OCI Signer] RPST token unavailable (refresh failed)", null);
            return null;
        }
        return new Material(session.token, session.sessionPrivateKey);
    }

    public static Material fromSecurityToken(Profile p,
                                             Consumer<String> infoLog,
                                             Consumer<String> errorLog) {
        // Example:
        //   p.sessionToken = "/home/kali/.oci/sessions/TEST/token"
        //   p.sessionPrivateKeyPath = "/home/kali/.oci/sessions/TEST/oci_api_key.pem"
        // -> Material(token="<JWT>", privateKey=<RSA key>)
        String token = OciTokenUtils.resolveTokenValue(p.sessionToken);
        if (token == null || token.isBlank()) {
            logError(errorLog, infoLog, "[OCI Signer] Session token is missing.", null);
            return null;
        }
        try {
            PrivateKey pk = OciPrivateKeyCache.loadRsaPrivateKey(
                    OciTokenUtils.expandHome(nz(p.sessionPrivateKeyPath)),
                    nz(p.sessionPrivateKeyPassphrase)
            );
            return new Material(token, pk);
        } catch (Exception e) {
            logError(errorLog, infoLog, "[OCI Signer] Failed to load session private key: " + e.getMessage(), e);
            return null;
        }
    }

    public static Material fromConfigProfile(Profile p,
                                             ConfigFileReader.ConfigFile cfg,
                                             Consumer<String> infoLog,
                                             Consumer<String> errorLog) {
        // Example input: config with security_token_file + key_file
        // Example output: Material(token="<JWT>", privateKey=<RSA key>)
        String tokenFile = (cfg == null) ? null : cfg.get("security_token_file");
        if (tokenFile == null || tokenFile.trim().isBlank()) {
            return null;
        }
        String token = OciTokenUtils.resolveTokenValue(tokenFile);
        if (token == null || token.isBlank()) {
            logError(errorLog, infoLog, "[OCI Signer] Session token is missing.", null);
            return null;
        }
        try {
            String keyFile = (cfg == null) ? "" : nz(cfg.get("key_file"));
            String passPhrase = (cfg == null) ? "" : nz(cfg.get("pass_phrase"));
            PrivateKey pk = OciPrivateKeyCache.loadRsaPrivateKey(
                    OciTokenUtils.expandHome(nz(keyFile)),
                    nz(passPhrase)
            );
            return new Material(token, pk);
        } catch (Exception e) {
            logError(errorLog, infoLog, "[OCI Signer] Failed to load session private key: " + e.getMessage(), e);
            return null;
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }

    private static void logError(Consumer<String> errorLog, Consumer<String> infoLog, String msg, Throwable t) {
        String detail = (t == null) ? "" : (" :: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        if (errorLog != null) errorLog.accept(msg + detail);
        if (infoLog != null) infoLog.accept(msg + detail);
    }
}
