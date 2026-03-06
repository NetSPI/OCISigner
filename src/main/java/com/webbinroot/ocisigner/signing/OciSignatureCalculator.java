package com.webbinroot.ocisigner.signing;

import com.oracle.bmc.http.signing.RequestSigner;
import com.webbinroot.ocisigner.auth.OciConfigProfileResolver;
import com.webbinroot.ocisigner.auth.OciCrypto;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.SigningMode;
import com.webbinroot.ocisigner.auth.OciRpstSessionManager;
import com.webbinroot.ocisigner.auth.OciSessionTokenResolver;
import com.webbinroot.ocisigner.auth.OciX509SessionManager;
import com.webbinroot.ocisigner.util.OciHttpDebug;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Signature Calculator (SDK-backed + Manual/custom).
 *
 * IMPORTANT:
 *  - SDK mode relies on OCI SDK RequestSigner (same as OciRequestSigner).
 *  - Manual mode relies on OciManualSigner (same as OciRequestSigner).
 *
 * Debug/canonicalization output:
 *  - OCI SDK does not expose its internal "string to sign".
 *    We reconstruct a pseudo signing string using Authorization headers="...".
 *  - Manual mode DOES have the true signing string, so we show it exactly.
 */
public final class OciSignatureCalculator {

    public static final class Result {
        /** Authorization header VALUE only (not including "Authorization: ") */
        public final String authorizationHeaderValue;

        /** SDK: reconstructed signing string; Manual: exact signing string */
        public final String reconstructedSigningString;

        /** headers="..." list from the Authorization value */
        public final String signedHeadersList;

        /** Big debug text for the modal */
        public final String debugText;

        public Result(String authorizationHeaderValue,
                      String reconstructedSigningString,
                      String signedHeadersList,
                      String debugText) {
            // Example output: authorizationHeaderValue="Signature ...", signedHeadersList="date (request-target) host"
            this.authorizationHeaderValue = authorizationHeaderValue;
            this.reconstructedSigningString = reconstructedSigningString;
            this.signedHeadersList = signedHeadersList;
            this.debugText = debugText;
        }
    }

    private static final Set<String> BODY_ALLOWED = Set.of("POST", "PUT", "PATCH");
    private static final DateTimeFormatter RFC1123 = DateTimeFormatter.RFC_1123_DATE_TIME;

    private OciSignatureCalculator() {}

    /**
     * Compute the Authorization Signature header.
     *
     * - SDK mode: uses OCI SDK signer
     * - Manual mode: uses OciManualSigner + the ManualSigningSettings from the profile
     *
     * Example input:
     *   GET https://objectstorage.us-phoenix-1.oraclecloud.com/n/
     * Example output:
     *   authorizationHeaderValue = "Signature ...", signedHeadersList = "date (request-target) host"
     */
    public static Result compute(Profile profile, ParsedRequest req) {
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(req, "req");

        SigningMode mode = (profile.signingMode == null) ? SigningMode.SDK : profile.signingMode;

        AuthType authType = (profile.authType() == null) ? AuthType.API_KEY : profile.authType();

        ManualSigningSettings manualSettings =
                (profile.manualSettings == null)
                        ? ManualSigningSettings.defaultsLikeSdk()
                        : profile.manualSettings;

        // Basic profile validation (auth-type specific)
        if (authType == AuthType.API_KEY) {
            if (isBlank(profile.tenancyOcid) || isBlank(profile.userOcid) || isBlank(profile.fingerprint)) {
                throw new IllegalArgumentException("Profile is missing tenancy OCID / user OCID / fingerprint.");
            }
            if (isBlank(profile.privateKeyPath)) {
                throw new IllegalArgumentException("Profile is missing private key file path.");
            }
        } else if (authType == AuthType.INSTANCE_PRINCIPAL) {
            if (!OciX509SessionManager.hasInstanceX509Inputs(profile)) {
                throw new IllegalArgumentException(
                        "Instance principal signing requires X.509 inputs in this calculator. " +
                                "Provide leaf cert/key (and optional intermediate certs) in the profile.");
            }
        } else if (authType == AuthType.RESOURCE_PRINCIPAL) {
            if (!OciRpstSessionManager.hasExplicitInputs(profile)) {
                throw new IllegalArgumentException(
                        "Resource principal signing requires RPST + private key inputs in this calculator.");
            }
        } else if (authType == AuthType.SECURITY_TOKEN) {
            if (isBlank(profile.sessionToken)
                    || isBlank(profile.sessionTenancyOcid)
                    || isBlank(profile.sessionFingerprint)
                    || isBlank(profile.sessionPrivateKeyPath)) {
                throw new IllegalArgumentException("Session token auth requires tenancy/fingerprint/key file and session token.");
            }
        } else if (authType == AuthType.CONFIG_PROFILE) {
            if (isBlank(profile.configFilePath)) {
                throw new IllegalArgumentException("Config profile auth requires OCI config file path.");
            }
        }

        // Parse/validate host
        String hostHeader = nz(req.headerValue("host"));
        if (hostHeader.isBlank()) {
            throw new IllegalArgumentException("Request is missing Host header.");
        }

        // Build URI for signing. Always https (matches OciRequestSigner fallback behavior)
        String requestTarget = OciSigningUtils.normalizeRequestTarget(req.requestTarget);
        URI uri = buildUriForSigning(hostHeader, requestTarget);
        boolean objectStoragePutSpecial =
                OciSigningUtils.isObjectStoragePutSpecial(req.method, uri.getHost(), requestTarget);

        // Build header multimap (lower-case keys), shared with request signer
        Map<String, List<String>> headerMultimap = OciSigningUtils.toHeaderMultimap(req.headers);
        boolean sdkExcludeBodyStrategy =
                objectStoragePutSpecial && !hasAnyObjectStorageBodyHeader(headerMultimap);

        // Ensure host exists (OciRequestSigner also does this)
        String uriHost = uri.getHost();
        if (uriHost != null && !uriHost.isBlank()) {
            headerMultimap.putIfAbsent("host", List.of(uriHost));
        }

        ManualSigningSettings tokenSigningSettings =
                (mode == SigningMode.MANUAL)
                        ? manualSettings
                        : ManualSigningSettings.defaultsLikeSdk();

        byte[] bodyBytes = (req.bodyBytes == null || req.bodyBytes.length == 0) ? null : req.bodyBytes;

        // -----------------------------
        // Instance Principal (manual session token)
        // -----------------------------
        if (authType == AuthType.INSTANCE_PRINCIPAL
                && OciX509SessionManager.hasInstanceX509Inputs(profile)) {
            OciSessionTokenResolver.Material session =
                    OciSessionTokenResolver.fromInstancePrincipal(profile, null, null, false);
            if (session == null || session.token == null || session.privateKey == null) {
                throw new IllegalStateException("Session token unavailable. Click Refresh Token in the UI first.");
            }
            return signWithSessionToken(
                    profile,
                    tokenSigningSettings,
                    req,
                    requestTarget,
                    uri,
                    headerMultimap,
                    bodyBytes,
                    session.token,
                    session.privateKey,
                    "Session token signer did not return an Authorization header."
            );
        }

        // -----------------------------
        // Resource Principal (manual session token)
        // -----------------------------
        if (authType == AuthType.RESOURCE_PRINCIPAL
                && OciRpstSessionManager.hasExplicitInputs(profile)) {
            OciSessionTokenResolver.Material session =
                    OciSessionTokenResolver.fromResourcePrincipal(profile, null, null, false);
            if (session == null || session.token == null || session.privateKey == null) {
                throw new IllegalStateException("RPST session token unavailable. Check RPST/key inputs.");
            }
            return signWithSessionToken(
                    profile,
                    tokenSigningSettings,
                    req,
                    requestTarget,
                    uri,
                    headerMultimap,
                    bodyBytes,
                    session.token,
                    session.privateKey,
                    "RPST signer did not return an Authorization header."
            );
        }

        // -----------------------------
        // Security Token (manual session token, no disk writes)
        // -----------------------------
        if (authType == AuthType.SECURITY_TOKEN) {
            OciSessionTokenResolver.Material session =
                    OciSessionTokenResolver.fromSecurityToken(profile, null, null);
            if (session == null || session.token == null || session.privateKey == null) {
                throw new IllegalStateException("Session token unavailable. Provide token + private key.");
            }
            return signWithSessionToken(
                    profile,
                    tokenSigningSettings,
                    req,
                    requestTarget,
                    uri,
                    headerMultimap,
                    bodyBytes,
                    session.token,
                    session.privateKey,
                    "Session token signer did not return an Authorization header."
            );
        }

        // -----------------------------
        // Manual (custom) mode
        // -----------------------------
        if (mode == SigningMode.MANUAL) {

            if (authType == AuthType.API_KEY) {
                OciManualSigner.Result r = OciManualSigner.sign(
                        profile,
                        manualSettings,
                        req.method,
                        requestTarget,
                        uri.getHost(),
                        headerMultimap,
                        bodyBytes
                );
                String authVal = r.headersToApply.get("authorization");
                if (authVal == null || authVal.isBlank()) {
                    throw new IllegalStateException("Manual signer did not return an Authorization header.");
                }
                String signedHeadersList = extractQuotedParam(authVal, "headers");
                if (signedHeadersList == null) signedHeadersList = "";
                String signingString = (r.signingString == null) ? "" : r.signingString;
                String debug = r.debugText == null ? "" : r.debugText;
                return new Result(authVal, signingString, signedHeadersList, debug);
            }

            if (authType == AuthType.SECURITY_TOKEN) {
                OciSessionTokenResolver.Material session =
                        OciSessionTokenResolver.fromSecurityToken(profile, null, null);
                if (session == null || session.token == null || session.privateKey == null) {
                    throw new IllegalArgumentException("Session token is missing.");
                }
                return signWithSessionToken(
                        profile,
                        manualSettings,
                        req,
                        requestTarget,
                        uri,
                        headerMultimap,
                        bodyBytes,
                        session.token,
                        session.privateKey,
                        "Session token signer did not return an Authorization header."
                );
            }

            if (authType == AuthType.CONFIG_PROFILE) {
                try {
                    OciConfigProfileResolver.ResolvedConfig resolved =
                            OciConfigProfileResolver.resolve(profile);
                    OciSessionTokenResolver.Material session =
                            OciSessionTokenResolver.fromConfigProfile(profile, resolved.config, null, null);
                    if (session != null) {
                        return signWithSessionToken(
                                profile,
                                manualSettings,
                                req,
                                requestTarget,
                                uri,
                                headerMultimap,
                                bodyBytes,
                                session.token,
                                session.privateKey,
                                "Session token signer did not return an Authorization header."
                        );
                    }

                    Profile tmp = OciConfigProfileResolver.apiKeyProfileFromConfig(resolved.config);

                    OciManualSigner.Result r = OciManualSigner.sign(
                            tmp,
                            manualSettings,
                            req.method,
                            requestTarget,
                            uri.getHost(),
                            headerMultimap,
                            bodyBytes
                    );
                    String authVal = r.headersToApply.get("authorization");
                    if (authVal == null || authVal.isBlank()) {
                        throw new IllegalStateException("Manual signer did not return an Authorization header.");
                    }
                    String signedHeadersList = extractQuotedParam(authVal, "headers");
                    if (signedHeadersList == null) signedHeadersList = "";
                    String signingString = (r.signingString == null) ? "" : r.signingString;
                    String debug = r.debugText == null ? "" : r.debugText;
                    return new Result(authVal, signingString, signedHeadersList, debug);
                } catch (Exception e) {
                    throw new IllegalArgumentException("Manual signing failed for Config Profile: " + e.getMessage(), e);
                }
            }

            if (authType == AuthType.INSTANCE_PRINCIPAL) {
                throw new IllegalArgumentException("Manual signing for Instance Principal requires X.509 inputs.");
            }
            if (authType == AuthType.RESOURCE_PRINCIPAL) {
                throw new IllegalArgumentException("Manual signing for Resource Principal requires RPST + key inputs.");
            }

            throw new IllegalArgumentException("Manual signing unsupported for auth type: " + authType);
        }

        // -----------------------------
        // SDK mode
        // -----------------------------

        // Body object rules (same as OciRequestSigner)
        Object bodyObj;

        if (BODY_ALLOWED.contains(req.method.toUpperCase(Locale.ROOT))) {
            String methodUpper = req.method.toUpperCase(Locale.ROOT);
            if ("PUT".equals(methodUpper) || "POST".equals(methodUpper)) {
                bodyObj = (bodyBytes == null) ? new byte[0] : bodyBytes;
            } else {
                bodyObj = (bodyBytes != null && bodyBytes.length > 0) ? bodyBytes : null;
            }
        } else {
            bodyObj = null;
        }

        // If neither date nor x-date is present, inject date for better UX/debug.
        boolean dateWasInjected = false;
        if (isBlank(first(headerMultimap.get("date"))) && isBlank(first(headerMultimap.get("x-date")))) {
            headerMultimap.put("date", List.of(RFC1123.format(ZonedDateTime.now(java.time.ZoneOffset.UTC))));
            dateWasInjected = true;
        }

        // Call OCI SDK signer (key point)
        RequestSigner signer = OciCrypto.sdkSignerFor(profile, sdkExcludeBodyStrategy);

        Map<String, String> signedHeaders = signer.signRequest(
                uri,
                req.method,
                headerMultimap,
                bodyObj
        );

        // Grab Authorization header value
        String authVal = getCaseInsensitive(signedHeaders, "authorization");
        if (authVal == null || authVal.isBlank()) {
            throw new IllegalStateException("OCI SDK signer did not return an Authorization header.");
        }

        // Extract headers="..." list from auth header (for debug)
        String signedHeadersList = extractQuotedParam(authVal, "headers");
        if (signedHeadersList == null) signedHeadersList = "";

        // Reconstruct signing string from headers list + actual values used
        String reconstructed = reconstructSigningString(
                signedHeadersList,
                req.method,
                requestTarget,
                signedHeaders,
                headerMultimap
        );

        // Build a debug dump for the modal
        String debug = buildDebug(
                profile,
                req,
                uri,
                signedHeaders,
                headerMultimap,
                authVal,
                signedHeadersList,
                reconstructed,
                dateWasInjected,
                objectStoragePutSpecial,
                sdkExcludeBodyStrategy
        );

        return new Result(authVal, reconstructed, signedHeadersList, debug);
    }

    private static Result signWithSessionToken(Profile profile,
                                               ManualSigningSettings settings,
                                               ParsedRequest req,
                                               String requestTarget,
                                               URI uri,
                                               Map<String, List<String>> headerMultimap,
                                               byte[] bodyBytes,
                                               String token,
                                               PrivateKey pk,
                                               String missingAuthMsg) {
        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                profile,
                token,
                pk,
                settings,
                req.method,
                requestTarget,
                uri.getHost(),
                headerMultimap,
                bodyBytes
        );
        String authVal = r.headersToApply.get("authorization");
        if (authVal == null || authVal.isBlank()) {
            throw new IllegalStateException(missingAuthMsg);
        }
        String signedHeadersList = extractQuotedParam(authVal, "headers");
        if (signedHeadersList == null) signedHeadersList = "";
        String debug = buildSessionTokenDebug(profile, req, uri, authVal, signedHeadersList, r.signingString, r.debugText);
        return new Result(authVal, r.signingString, signedHeadersList, debug);
    }

    // ------------------------------------------------------------------------
    // Debug helpers (SDK mode)
    // ------------------------------------------------------------------------

    private static String buildDebug(Profile profile,
                                     ParsedRequest req,
                                     URI uri,
                                     Map<String, String> signedHeaders,
                                     Map<String, List<String>> headerMultimap,
                                     String authorizationValue,
                                     String signedHeadersList,
                                     String reconstructedSigningString,
                                     boolean dateWasInjected,
                                     boolean objectStoragePutSpecial,
                                     boolean sdkExcludeBodyStrategy) {

        StringBuilder sb = new StringBuilder();
        sb.append("=== OCI Signature Calculator (SDK-backed) ===\n\n");

        sb.append("Profile:\n");
        sb.append("  name:        ").append(nz(profile.name())).append("\n");
        sb.append("  tenancy:     ").append(nz(profile.tenancyOcid)).append("\n");
        sb.append("  user:        ").append(nz(profile.userOcid)).append("\n");
        sb.append("  fingerprint: ").append(nz(profile.fingerprint)).append("\n");
        sb.append("  key_file:    ").append(nz(profile.privateKeyPath)).append("\n");
        sb.append("  mode:        ").append(String.valueOf(profile.signingMode)).append("\n\n");
        sb.append("  objectStoragePutSpecial: ").append(objectStoragePutSpecial).append("\n");
        sb.append("  sdkStrategy: ").append(sdkExcludeBodyStrategy ? "EXCLUDE_BODY" : "STANDARD").append("\n\n");

        sb.append("Request (pasted):\n");
        sb.append("  method: ").append(req.method).append("\n");
        sb.append("  target: ").append(req.requestTarget).append("\n");
        sb.append("  uri:    ").append(uri).append("\n\n");

        sb.append("Headers passed into OCI SDK signer (multimap; lower-cased keys):\n");
        sb.append(OciHttpDebug.formatHeaderMultimap(headerMultimap));
        if (dateWasInjected) {
            sb.append("  (note) date was injected by calculator for convenience\n");
        }
        sb.append("\n");

        sb.append("Headers returned by OCI SDK signer:\n");
        sb.append(OciHttpDebug.formatHeaderMap(signedHeaders));
        sb.append("\n");

        sb.append("Authorization (value):\n");
        sb.append("  ").append(authorizationValue).append("\n\n");

        sb.append("Signed headers list (from Authorization headers=\"...\"):\n");
        sb.append("  ").append(signedHeadersList).append("\n\n");

        sb.append("Reconstructed signing string (pseudo — based on headers list + values):\n");
        sb.append(reconstructedSigningString).append("\n");

        return sb.toString();
    }

    private static String buildSessionTokenDebug(Profile profile,
                                                 ParsedRequest req,
                                                 URI uri,
                                                 String authorizationValue,
                                                 String signedHeadersList,
                                                 String signingString,
                                                 String signerDebug) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== OCI Signature Calculator (Session Token) ===\n\n");

        sb.append("Profile:\n");
        sb.append("  name:        ").append(nz(profile.name())).append("\n");
        sb.append("  auth_type:   ").append(String.valueOf(profile.authType())).append("\n");
        sb.append("  mode:        ").append(String.valueOf(profile.signingMode)).append("\n\n");

        sb.append("Request (pasted):\n");
        sb.append("  method: ").append(req.method).append("\n");
        sb.append("  target: ").append(req.requestTarget).append("\n");
        sb.append("  uri:    ").append(uri).append("\n\n");

        sb.append("Authorization (value):\n");
        sb.append("  ").append(authorizationValue).append("\n\n");

        sb.append("Signed headers list:\n");
        sb.append("  ").append(signedHeadersList).append("\n\n");

        sb.append("Signing string:\n");
        sb.append(signingString).append("\n\n");

        if (signerDebug != null && !signerDebug.isBlank()) {
            sb.append("Signer debug:\n");
            sb.append(signerDebug).append("\n");
        }

        return sb.toString();
    }

    // ------------------------------------------------------------------------
    // Canonicalization reconstruction (SDK pseudo)
    // ------------------------------------------------------------------------

    private static String reconstructSigningString(String headersList,
                                                   String method,
                                                   String requestTarget,
                                                   Map<String, String> signedHeaders,
                                                   Map<String, List<String>> headerMultimap) {

        List<String> headers = new ArrayList<>();
        if (headersList != null && !headersList.isBlank()) {
            headers.addAll(Arrays.asList(headersList.trim().split("\\s+")));
        } else {
            // fallback guess if not present
            headers = isBlank(first(headerMultimap.get("x-date")))
                    ? List.of("(request-target)", "date", "host")
                    : List.of("(request-target)", "x-date", "host");
        }

        StringBuilder sb = new StringBuilder();
        String methodLower = method.toLowerCase(Locale.ROOT);

        for (int i = 0; i < headers.size(); i++) {
            String h = headers.get(i);

            if ("(request-target)".equalsIgnoreCase(h)) {
                sb.append("(request-target): ").append(methodLower).append(" ").append(requestTarget);
            } else {
                String key = h.toLowerCase(Locale.ROOT);

                // Prefer SDK-returned values, else fallback to original multimap
                String v = getCaseInsensitive(signedHeaders, key);
                if (v == null || v.isBlank()) {
                    v = first(headerMultimap.get(key));
                }
                if (v == null) v = "";

                sb.append(key).append(": ").append(v);
            }

            if (i < headers.size() - 1) sb.append("\n");
        }

        return sb.toString();
    }

    // ------------------------------------------------------------------------
    // Raw HTTP parsing model + parser
    // ------------------------------------------------------------------------

    public static final class ParsedRequest {
        public final String method;
        public final String requestTarget; // path + optional query, starts with "/"
        public final Map<String, List<String>> headers; // lower-case key -> values
        public final byte[] bodyBytes;

        /**
         * Parsed request model used by the calculator.
         * Example input: method="GET", requestTarget="/n/", headers={"host":["..."]}
         */
        public ParsedRequest(String method,
                             String requestTarget,
                             Map<String, List<String>> headers,
                             byte[] bodyBytes) {
            this.method = method;
            this.requestTarget = requestTarget;
            this.headers = headers;
            this.bodyBytes = bodyBytes;
        }

        /**
         * Get the first header value by name (case-insensitive).
         * Example input: "host" -> "objectstorage.us-phoenix-1.oraclecloud.com"
         */
        public String headerValue(String name) {
            List<String> v = headers.get(name.toLowerCase(Locale.ROOT));
            if (v == null || v.isEmpty()) return "";
            return v.get(0);
        }
    }

    /**
     * Parse a raw HTTP request pasted by the user.
     * Accepts CRLF or LF. Body bytes are UTF-8 of the pasted body.
     *
     * Example input:
     *  GET /n/ HTTP/1.1\nHost: objectstorage.us-phoenix-1.oraclecloud.com\n\n
     * Example output:
     *  ParsedRequest(method="GET", requestTarget="/n/", headers={"host":["..."]})
     */
    public static ParsedRequest parseRawHttpRequest(String raw) {
        if (raw == null) raw = "";
        String normalized = raw.replace("\r\n", "\n");

        int split = normalized.indexOf("\n\n");
        String head = (split >= 0) ? normalized.substring(0, split) : normalized;
        String body = (split >= 0) ? normalized.substring(split + 2) : "";

        String[] lines = head.split("\n");
        if (lines.length == 0 || lines[0].trim().isEmpty()) {
            throw new IllegalArgumentException("Request is empty or missing request line.");
        }

        String requestLine = lines[0].trim();
        String[] parts = requestLine.split("\\s+");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid request line: " + requestLine);
        }

        String method = parts[0].trim();
        String target = parts[1].trim();

        // If absolute URL was pasted, reduce to path+query
        if (target.startsWith("http://") || target.startsWith("https://")) {
            try {
                URI u = URI.create(target);
                String p = u.getRawPath();
                String q = u.getRawQuery();
                if (p == null || p.isBlank()) p = "/";
                target = (q == null) ? p : (p + "?" + q);
            } catch (Exception ignored) {}
        }

        if (!target.startsWith("/")) target = "/" + target;

        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            String ln = lines[i];
            if (ln == null) continue;
            if (ln.trim().isEmpty()) continue;

            int idx = ln.indexOf(':');
            if (idx <= 0) continue;

            String k = ln.substring(0, idx).trim().toLowerCase(Locale.ROOT);
            String v = ln.substring(idx + 1).trim();

            headers.computeIfAbsent(k, kk -> new ArrayList<>()).add(v == null ? "" : v);
        }

        byte[] bodyBytes = body.isEmpty() ? null : body.getBytes(StandardCharsets.UTF_8);
        return new ParsedRequest(method, target, headers, bodyBytes);
    }

    // ------------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------------

    private static URI buildUriForSigning(String hostHeader, String requestTarget) {
        // Host may include port; URI.create handles "example.com:8443"
        String scheme = "https";
        String host = hostHeader.trim();

        // Strip any accidental scheme if user pasted it in Host (rare)
        if (host.startsWith("http://")) host = host.substring("http://".length());
        if (host.startsWith("https://")) host = host.substring("https://".length());

        String target = OciSigningUtils.normalizeRequestTarget(requestTarget);
        return URI.create(scheme + "://" + host + target);
    }


    private static String extractQuotedParam(String authorizationValue, String param) {
        // e.g. headers="(request-target) date host ..."
        if (authorizationValue == null) return null;
        String needle = param + "=\"";
        int i = authorizationValue.indexOf(needle);
        if (i < 0) return null;
        int start = i + needle.length();
        int end = authorizationValue.indexOf('"', start);
        if (end < 0) return null;
        return authorizationValue.substring(start, end);
    }

    private static String getCaseInsensitive(Map<String, String> m, String key) {
        if (m == null || key == null) return null;
        String direct = m.get(key);
        if (direct != null) return direct;
        String k2 = key.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, String> e : m.entrySet()) {
            if (e.getKey() != null && e.getKey().toLowerCase(Locale.ROOT).equals(k2)) {
                return e.getValue();
            }
        }
        return null;
    }

    private static String first(List<String> vals) {
        if (vals == null || vals.isEmpty()) return null;
        return vals.get(0);
    }

    private static boolean hasAnyObjectStorageBodyHeader(Map<String, List<String>> headers) {
        if (headers == null) return false;
        return hasHeaderValue(headers, "x-content-sha256")
                || hasHeaderValue(headers, "content-type")
                || hasHeaderValue(headers, "content-length");
    }

    private static boolean hasHeaderValue(Map<String, List<String>> headers, String name) {
        List<String> vals = headers.get(name);
        if (vals == null || vals.isEmpty()) return false;
        for (String v : vals) {
            if (v != null && !v.trim().isEmpty()) return true;
        }
        return false;
    }

    private static String nz(String s) {
        return (s == null) ? "" : s.trim();
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
