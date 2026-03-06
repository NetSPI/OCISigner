package com.webbinroot.ocisigner.signing;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.oracle.bmc.http.client.io.DuplicatableInputStream;
import com.oracle.bmc.http.signing.RequestSigner;
import com.webbinroot.ocisigner.auth.OciConfigProfileResolver;
import com.webbinroot.ocisigner.auth.OciCrypto;
import com.webbinroot.ocisigner.auth.OciRpstSessionManager;
import com.webbinroot.ocisigner.auth.OciSessionTokenResolver;
import com.webbinroot.ocisigner.auth.OciX509SessionManager;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.SigningMode;
import com.webbinroot.ocisigner.util.OciHttpDebug;

import java.lang.reflect.Method;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Consumer;

public final class OciRequestSigner {

    private OciRequestSigner() {}

    private static final Set<String> BODY_ALLOWED =
            Set.of("POST", "PUT", "PATCH");
    private static final String INTERNAL_TEST_HEADER = "X-Oci-Signer-Test";

    private static final class SigningContext {
        final Profile profile;
        final HttpRequest working;
        final URI uri;
        final Map<String, List<String>> headerMultimap;
        final byte[] bodyBytes;
        final Object bodyObj;
        final boolean sdkExcludeBodyStrategy;
        final boolean objectStoragePutSpecial;
        final String requestTarget;
        final Consumer<String> infoLog;
        final Consumer<String> errorLog;
        final boolean debug;

        SigningContext(Profile profile,
                       HttpRequest working,
                       URI uri,
                       Map<String, List<String>> headerMultimap,
                       byte[] bodyBytes,
                       Object bodyObj,
                       boolean sdkExcludeBodyStrategy,
                       boolean objectStoragePutSpecial,
                       String requestTarget,
                       Consumer<String> infoLog,
                       Consumer<String> errorLog,
                       boolean debug) {
            this.profile = profile;
            this.working = working;
            this.uri = uri;
            this.headerMultimap = headerMultimap;
            this.bodyBytes = bodyBytes;
            this.bodyObj = bodyObj;
            this.sdkExcludeBodyStrategy = sdkExcludeBodyStrategy;
            this.objectStoragePutSpecial = objectStoragePutSpecial;
            this.requestTarget = requestTarget;
            this.infoLog = infoLog;
            this.errorLog = errorLog;
            this.debug = debug;
        }
    }

    private interface SignerStrategy {
        HttpRequest sign(SigningContext ctx) throws Exception;
    }

    /**
     * Sign a Montoya HttpRequest and return a modified request with OCI headers.
     *
     * Example input:
     *  GET /n/ HTTP/1.1 + Host: objectstorage.<region>.oraclecloud.com
     * Example output:
     *  Same request + Date + Authorization headers
     */
    public static HttpRequest sign(HttpRequest req,
                                   Profile profile,
                                   Consumer<String> infoLog,
                                   Consumer<String> errorLog,
                                   boolean debug) {
        Objects.requireNonNull(req, "request");
        Objects.requireNonNull(profile, "profile");

        // Example input:
        //   GET /n/ HTTP/1.1
        //   Host: objectstorage.us-phoenix-1.oraclecloud.com
        // Example output (added by this signer):
        //   Date: Wed, 04 Mar 2026 01:30:11 GMT
        //   Authorization: Signature ... (rsa-sha256)
        logInfo(infoLog, "[OCI Signer] Profile: " + profile.name()
                + " | Auth: " + profile.authType()
                + " | Mode: " + profile.signingMode
                + " | InScopeOnly: " + profile.onlyInScope);

        logDebug(infoLog, debug, "[OCI Signer] ===== HTTP REQUEST BEFORE =====");
        logDebug(infoLog, debug, OciHttpDebug.dumpMontoyaRequest(req));

        HttpRequest working = req;
        boolean forceSign = hasHeader(working, INTERNAL_TEST_HEADER);
        if (forceSign) {
            working = removeHeader(working, INTERNAL_TEST_HEADER);
        }

        if (!forceSign && profile.onlyWithAuthHeader && !hasHeader(working, "Authorization")) {
            logInfo(infoLog, "[OCI Signer] Skipped (no Authorization header present)");
            return working;
        }

        // Optional date update (for Repeater re-sends)
        if (profile.updateTimestamp) {
            String now = DateTimeFormatter.RFC_1123_DATE_TIME.format(
                    ZonedDateTime.now(java.time.ZoneOffset.UTC)
            );
            boolean hasXDate = hasHeader(working, "x-date");
            boolean hasDate = hasHeader(working, "date");

            if (hasXDate) {
                working = working.withUpdatedHeader("x-date", now);
            }
            if (hasDate) {
                working = working.withUpdatedHeader("date", now);
            }
            if (!hasXDate && !hasDate) {
                working = working.withUpdatedHeader("date", now);
            }
        }

        // If raw path contains illegal quote, encode it so signing + wire bytes match
        String rawPath = working.path(); // includes query
        if (rawPath != null && rawPath.contains("\"")) {
            String fixedPath = rawPath.replace("\"", "%22");
            logInfo(infoLog, "[OCI Signer] WARNING: Detected raw '\"' in URL. Encoding to %22 for signing.");

            // Try to update request path if Montoya supports it (reflection keeps compile-safe)
            working = tryWithPath(working, fixedPath);
        }

        // Build URI for signing from scheme + host + path
        URI uri = buildUriForSigning(working);

        // Avoid signing federation calls when proxying through Burp (prevents recursion / hangs).
        if (!forceSign && isFederationRequest(profile, uri)) {
            logInfo(infoLog, "[OCI Signer] Skipped (federation endpoint): " + uri);
            return working;
        }

        logDebug(infoLog, debug, "[OCI Signer] ===== STANDARDIZED REQUEST =====");
        logDebug(infoLog, debug, "[OCI Signer] Method: " + working.method());
        logDebug(infoLog, debug, "[OCI Signer] URL:    " + uri);

        Map<String, List<String>> headerMultimap = OciSigningUtils.toHeaderMultimap(working.headers());

        String host = uri.getHost();
        if (host != null && !host.isBlank()) {
            headerMultimap.putIfAbsent("host", List.of(host));
        }

        Object bodyObj;
        byte[] bodyBytes = (working.body() == null) ? null : working.body().getBytes();

        if (BODY_ALLOWED.contains(working.method().toUpperCase(Locale.ROOT))) {
            String method = working.method().toUpperCase(Locale.ROOT);
            byte[] sdkBodyBytes = (bodyBytes == null) ? new byte[0] : bodyBytes;
            if ("PUT".equals(method) || "POST".equals(method)) {
                // OCI SDK signer expects stream body types (not raw byte[]) for body hashing.
                bodyObj = new ByteArrayDuplicatableInputStream(sdkBodyBytes);
            } else {
                bodyObj = (bodyBytes != null && bodyBytes.length > 0)
                        ? new ByteArrayDuplicatableInputStream(sdkBodyBytes)
                        : null;
            }
        } else {
            bodyObj = null;
        }

        String requestTarget = OciSigningUtils.normalizeRequestTarget(working.path());
        boolean objectStoragePutSpecial =
                OciSigningUtils.isObjectStoragePutSpecial(working.method(), uri.getHost(), requestTarget);
        boolean hasXContentSha256 = hasHeaderValue(headerMultimap, "x-content-sha256");
        boolean hasAnyObjectStorageBodyHeader = hasAnyObjectStorageBodyHeader(headerMultimap);
        boolean sdkExcludeBodyStrategy =
                objectStoragePutSpecial && !hasAnyObjectStorageBodyHeader;
        logDebug(infoLog, debug, "[OCI Signer] ObjectStoragePUT special-case: " + objectStoragePutSpecial);
        logDebug(infoLog, debug, "[OCI Signer] ObjectStoragePUT has x-content-sha256: " + hasXContentSha256);
        logDebug(infoLog, debug, "[OCI Signer] ObjectStoragePUT has any body header: " + hasAnyObjectStorageBodyHeader);
        logDebug(infoLog, debug, "[OCI Signer] SDK strategy: "
                + (sdkExcludeBodyStrategy ? "EXCLUDE_BODY" : "STANDARD"));

        SigningContext ctx = new SigningContext(
                profile,
                working,
                uri,
                headerMultimap,
                bodyBytes,
                bodyObj,
                sdkExcludeBodyStrategy,
                objectStoragePutSpecial,
                requestTarget,
                infoLog,
                errorLog,
                debug
        );

        try {
            SignerStrategy strategy = chooseStrategy(ctx);
            return strategy.sign(ctx);
        } catch (Exception ex) {
            logError(errorLog, infoLog, "[OCI Signer] Signing failed", ex);
            logStack(infoLog, "[OCI Signer] Signing failed (stack)", ex);
            // Do not send partially mutated headers (e.g. updated date with stale auth).
            // Fall back to the exact original request object on signing failure.
            return req;
        }
    }

    private static SignerStrategy chooseStrategy(SigningContext ctx) {
        if (ctx.profile.signingMode == SigningMode.MANUAL) return new ManualStrategy();

        AuthType at = (ctx.profile.authType() == null) ? AuthType.API_KEY : ctx.profile.authType();
        if (at == AuthType.INSTANCE_PRINCIPAL && OciX509SessionManager.hasInstanceX509Inputs(ctx.profile)) {
            return new InstancePrincipalStrategy();
        }
        if (at == AuthType.RESOURCE_PRINCIPAL && OciRpstSessionManager.hasExplicitInputs(ctx.profile)) {
            return new ResourcePrincipalStrategy();
        }
        if (at == AuthType.SECURITY_TOKEN) {
            return new SecurityTokenStrategy();
        }
        return new SdkStrategy();
    }

    private static final class ManualStrategy implements SignerStrategy {
        @Override
        public HttpRequest sign(SigningContext ctx) throws Exception {
            ManualSigningSettings ms =
                    (ctx.profile.manualSettings == null)
                            ? ManualSigningSettings.defaultsLikeSdk()
                            : ctx.profile.manualSettings;

            AuthType at = (ctx.profile.authType() == null) ? AuthType.API_KEY : ctx.profile.authType();

            if (at == AuthType.API_KEY) {
                OciManualSigner.Result r = OciManualSigner.sign(
                        ctx.profile,
                        ms,
                        ctx.working.method(),
                        ctx.requestTarget,
                        ctx.uri.getHost(),
                        ctx.headerMultimap,
                        ctx.bodyBytes
                );

                logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] ===== MANUAL SIGNATURE CALCULATED =====");
                for (Map.Entry<String, String> e : r.headersToApply.entrySet()) {
                    logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] " + e.getKey() + ": " + e.getValue());
                }
                logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] ===== MANUAL DEBUG =====");
                logDebug(ctx.infoLog, ctx.debug, r.debugText);

                HttpRequest out = applyHeaders(ctx.working, r.headersToApply);

                logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] ===== FINAL HTTP REQUEST =====");
                logDebug(ctx.infoLog, ctx.debug, OciHttpDebug.dumpMontoyaRequest(out));
                return out;
            }

            if (at == AuthType.INSTANCE_PRINCIPAL) {
                OciSessionTokenResolver.Material material = sessionFromInstancePrincipal(ctx);
                if (material == null) return ctx.working;
                return signWithSessionToken(ctx, ms, material, "SESSION TOKEN SIGNATURE");
            }

            if (at == AuthType.RESOURCE_PRINCIPAL) {
                OciSessionTokenResolver.Material material = sessionFromResourcePrincipal(ctx);
                if (material == null) return ctx.working;
                return signWithSessionToken(ctx, ms, material, "RPST SESSION TOKEN SIGNATURE");
            }

            if (at == AuthType.SECURITY_TOKEN) {
                OciSessionTokenResolver.Material material = sessionFromSecurityToken(ctx);
                if (material == null) return ctx.working;
                return signWithSessionToken(ctx, ms, material, "SESSION TOKEN SIGNATURE");
            }

            if (at == AuthType.CONFIG_PROFILE) {
                try {
                    OciConfigProfileResolver.ResolvedConfig resolved =
                            OciConfigProfileResolver.resolve(ctx.profile);
                    OciSessionTokenResolver.Material material =
                            OciSessionTokenResolver.fromConfigProfile(
                                    ctx.profile,
                                    resolved.config,
                                    ctx.infoLog,
                                    ctx.errorLog
                            );
                    if (material != null) {
                        return signWithSessionToken(ctx, ms, material, "SESSION TOKEN SIGNATURE");
                    }

                    // API key profile
                    Profile tmp = OciConfigProfileResolver.apiKeyProfileFromConfig(resolved.config);
                    OciManualSigner.Result r = OciManualSigner.sign(
                            tmp,
                            ms,
                            ctx.working.method(),
                            ctx.requestTarget,
                            ctx.uri.getHost(),
                            ctx.headerMultimap,
                            ctx.bodyBytes
                    );
                    return applyHeaders(ctx.working, r.headersToApply);
                } catch (Exception e) {
                    logError(ctx.errorLog, ctx.infoLog, "[OCI Signer] Manual signing failed for Config Profile: " + e.getMessage(), e);
                    return ctx.working;
                }
            }

            logError(ctx.errorLog, ctx.infoLog, "[OCI Signer] Manual signing unsupported for auth type: " + at, null);
            return ctx.working;
        }
    }

    private static final class InstancePrincipalStrategy implements SignerStrategy {
        @Override
        public HttpRequest sign(SigningContext ctx) throws Exception {
            logInfo(ctx.infoLog, "[OCI Signer] Manual X509 session token signing (instance principal)");
            ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
            OciSessionTokenResolver.Material material = sessionFromInstancePrincipal(ctx);
            if (material == null) return ctx.working;
            return signWithSessionToken(ctx, ms, material, "SESSION TOKEN SIGNATURE");
        }
    }

    private static final class ResourcePrincipalStrategy implements SignerStrategy {
        @Override
        public HttpRequest sign(SigningContext ctx) throws Exception {
            logInfo(ctx.infoLog, "[OCI Signer] Manual RPST session token signing (resource principal)");
            ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
            OciSessionTokenResolver.Material material = sessionFromResourcePrincipal(ctx);
            if (material == null) return ctx.working;
            return signWithSessionToken(ctx, ms, material, "RPST SESSION TOKEN SIGNATURE");
        }
    }

    private static final class SecurityTokenStrategy implements SignerStrategy {
        @Override
        public HttpRequest sign(SigningContext ctx) throws Exception {
            logInfo(ctx.infoLog, "[OCI Signer] Manual session token signing (security token)");
            ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
            OciSessionTokenResolver.Material material = sessionFromSecurityToken(ctx);
            if (material == null) return ctx.working;
            return signWithSessionToken(ctx, ms, material, "SESSION TOKEN SIGNATURE");
        }
    }

    private static final class SdkStrategy implements SignerStrategy {
        @Override
        public HttpRequest sign(SigningContext ctx) throws Exception {
            logInfo(ctx.infoLog, "[OCI Signer] SDK signing using auth type: " + ctx.profile.authType()
                    + " | thread=" + Thread.currentThread().getName());

            AuthType at = (ctx.profile.authType() == null) ? AuthType.API_KEY : ctx.profile.authType();
            if (ctx.objectStoragePutSpecial && (at == AuthType.API_KEY || at == AuthType.CONFIG_PROFILE)) {
                logInfo(ctx.infoLog, "[OCI Signer] ObjectStorage special-case: manual include-present signing for " + at);
                return signObjectStorageSpecialManual(ctx);
            }

            long startNs = System.nanoTime();
            RequestSigner signer = OciCrypto.sdkSignerFor(ctx.profile, ctx.sdkExcludeBodyStrategy);
            logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] SDK body object class: "
                    + (ctx.bodyObj == null ? "null" : ctx.bodyObj.getClass().getName()));

            Map<String, String> signedHeaders;
            Thread t = Thread.currentThread();
            ClassLoader prev = t.getContextClassLoader();
            ClassLoader cl = OciRequestSigner.class.getClassLoader();
            try {
                // OCI SDK provider lookup uses ServiceLoader; force extension classloader.
                t.setContextClassLoader(cl);
                signedHeaders = signer.signRequest(
                        ctx.uri,
                        ctx.working.method(),
                        ctx.headerMultimap,
                        ctx.bodyObj
                );
            } finally {
                t.setContextClassLoader(prev);
            }
            long tookMs = (System.nanoTime() - startNs) / 1_000_000;
            logInfo(ctx.infoLog, "[OCI Signer] SDK signRequest completed in " + tookMs + " ms");

            logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] ===== SIGNATURE CALCULATED =====");
            for (Map.Entry<String, String> e : signedHeaders.entrySet()) {
                logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] " + e.getKey() + ": " + e.getValue());
            }

            HttpRequest out = applyHeaders(ctx.working, signedHeaders);

            logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] ===== FINAL HTTP REQUEST =====");
            logDebug(ctx.infoLog, ctx.debug, OciHttpDebug.dumpMontoyaRequest(out));

            return out;
        }
    }

    private static HttpRequest signObjectStorageSpecialManual(SigningContext ctx) throws Exception {
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        AuthType at = (ctx.profile.authType() == null) ? AuthType.API_KEY : ctx.profile.authType();

        if (at == AuthType.API_KEY) {
            OciManualSigner.Result r = OciManualSigner.sign(
                    ctx.profile,
                    ms,
                    ctx.working.method(),
                    ctx.requestTarget,
                    ctx.uri.getHost(),
                    ctx.headerMultimap,
                    ctx.bodyBytes
            );
            return applyHeaders(ctx.working, r.headersToApply);
        }

        if (at == AuthType.CONFIG_PROFILE) {
            OciConfigProfileResolver.ResolvedConfig resolved =
                    OciConfigProfileResolver.resolve(ctx.profile);
            OciSessionTokenResolver.Material material =
                    OciSessionTokenResolver.fromConfigProfile(
                            ctx.profile,
                            resolved.config,
                            ctx.infoLog,
                            ctx.errorLog
                    );
            if (material != null) {
                return signWithSessionToken(ctx, ms, material, "SESSION TOKEN SIGNATURE");
            }

            Profile tmp = OciConfigProfileResolver.apiKeyProfileFromConfig(resolved.config);
            OciManualSigner.Result r = OciManualSigner.sign(
                    tmp,
                    ms,
                    ctx.working.method(),
                    ctx.requestTarget,
                    ctx.uri.getHost(),
                    ctx.headerMultimap,
                    ctx.bodyBytes
            );
            return applyHeaders(ctx.working, r.headersToApply);
        }

        return ctx.working;
    }

    private static HttpRequest signWithSessionToken(SigningContext ctx,
                                                    ManualSigningSettings ms,
                                                    OciSessionTokenResolver.Material material,
                                                    String debugLabel) {
        if (material == null) return ctx.working;
        if (material.token == null || material.token.isBlank() || material.privateKey == null) {
            logError(ctx.errorLog, ctx.infoLog, "[OCI Signer] Session token unavailable (refresh failed)", null);
            return ctx.working;
        }

        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                ctx.profile,
                material.token,
                material.privateKey,
                ms,
                ctx.working.method(),
                ctx.requestTarget,
                ctx.uri.getHost(),
                ctx.headerMultimap,
                ctx.bodyBytes
        );

        if (ctx.debug && ctx.infoLog != null && debugLabel != null) {
            logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] ===== " + debugLabel + " =====");
            for (Map.Entry<String, String> e : r.headersToApply.entrySet()) {
                logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] " + e.getKey() + ": " + e.getValue());
            }
        }

        HttpRequest out = applyHeaders(ctx.working, r.headersToApply);
        logDebug(ctx.infoLog, ctx.debug, "[OCI Signer] ===== FINAL HTTP REQUEST =====");
        logDebug(ctx.infoLog, ctx.debug, OciHttpDebug.dumpMontoyaRequest(out));
        return out;
    }

    private static OciSessionTokenResolver.Material sessionFromInstancePrincipal(SigningContext ctx) {
        return OciSessionTokenResolver.fromInstancePrincipal(ctx.profile, ctx.infoLog, ctx.errorLog, false);
    }

    private static OciSessionTokenResolver.Material sessionFromResourcePrincipal(SigningContext ctx) {
        return OciSessionTokenResolver.fromResourcePrincipal(ctx.profile, ctx.infoLog, ctx.errorLog, false);
    }

    private static OciSessionTokenResolver.Material sessionFromSecurityToken(SigningContext ctx) {
        return OciSessionTokenResolver.fromSecurityToken(ctx.profile, ctx.infoLog, ctx.errorLog);
    }

    private static HttpRequest tryWithPath(HttpRequest req, String newPath) {
        try {
            Method m = req.getClass().getMethod("withPath", String.class);
            Object out = m.invoke(req, newPath);
            if (out instanceof HttpRequest) return (HttpRequest) out;
        } catch (Exception ignored) {}
        return req;
    }

    private static URI buildUriForSigning(HttpRequest req) {
        String scheme = "https";
        String host = safe(req.headerValue("Host"));

        // Try to use req.url() if it is a java.net.URL (older Montoya)
        try {
            Object u = req.url();
            if (u instanceof URL) {
                scheme = ((URL) u).getProtocol();
                if (host.isBlank()) host = ((URL) u).getHost();
            }
        } catch (Exception ignored) {}

        if (host.isBlank()) host = "localhost";

        String path = OciSigningUtils.normalizeRequestTarget(req.path());

        return URI.create(scheme + "://" + host + path);
    }

    private static boolean isFederationRequest(Profile profile, URI uri) {
        if (profile == null || uri == null) return false;
        AuthType type = profile.authType();
        if (type != AuthType.INSTANCE_PRINCIPAL && type != AuthType.RESOURCE_PRINCIPAL && type != AuthType.SECURITY_TOKEN) {
            return false;
        }

        String host = safe(uri.getHost()).toLowerCase(Locale.ROOT);
        String path = safe(uri.getPath()).toLowerCase(Locale.ROOT);
        if (host.isBlank()) return false;

        // Always skip federation token calls to /v1/x509 to avoid recursion.
        if (path.contains("/v1/x509")) {
            return true;
        }

        // Match auth.<region>.oraclecloud.com federation calls.
        if (host.startsWith("auth.") && host.endsWith(".oraclecloud.com")) {
            return true;
        }

        // Also match explicit federation endpoint if user provided one.
        String fed = safe(profile.instanceX509FederationEndpoint);
        if (!fed.isBlank()) {
            try {
                URI fedUri = URI.create(fed);
                String fedHost = safe(fedUri.getHost()).toLowerCase(Locale.ROOT);
                if (!fedHost.isBlank() && fedHost.equals(host)) {
                    return true;
                }
            } catch (Exception ignored) {}
        }

        return false;
    }

    private static HttpRequest applyHeaders(HttpRequest base, Map<String, String> headersToApply) {
        HttpRequest out = base;
        if (headersToApply == null) return out;
        for (Map.Entry<String, String> e : headersToApply.entrySet()) {
            String name = e.getKey();
            String val = e.getValue();
            if (name != null && val != null) {
                String headerName = normalizeHeaderName(name);
                if (hasHeader(out, headerName)) {
                    out = out.withUpdatedHeader(headerName, val);
                } else {
                    try {
                        out = out.withAddedHeader(headerName, val);
                    } catch (Exception ignored) {
                        // Fallback in case withAddedHeader is unavailable in older API.
                        out = out.withUpdatedHeader(headerName, val);
                    }
                }
            }
        }
        return out;
    }

    private static String normalizeHeaderName(String name) {
        if (name == null) return null;
        String n = name.trim();
        String lower = n.toLowerCase(Locale.ROOT);
        if ("authorization".equals(lower)) return "Authorization";
        if ("date".equals(lower)) return "Date";
        if ("host".equals(lower)) return "Host";
        return n;
    }

    private static boolean hasHeader(HttpRequest req, String name) {
        if (req == null || name == null) return false;
        String target = name.trim().toLowerCase(Locale.ROOT);
        for (HttpHeader h : req.headers()) {
            if (h == null || h.name() == null) continue;
            if (h.name().trim().toLowerCase(Locale.ROOT).equals(target)) {
                return true;
            }
        }
        return false;
    }

    private static HttpRequest removeHeader(HttpRequest req, String name) {
        if (req == null || name == null) return req;
        try {
            return req.withRemovedHeader(name);
        } catch (Exception ignored) {
            return req;
        }
    }

    private static void logInfo(Consumer<String> log, String msg) {
        if (log != null && msg != null) log.accept(msg);
    }

    private static void logDebug(Consumer<String> log, boolean debug, String msg) {
        if (debug && log != null && msg != null) log.accept(msg);
    }

    private static void logError(Consumer<String> errorLog, Consumer<String> infoLog, String msg, Throwable t) {
        String detail = (t == null) ? "" : (" :: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        if (errorLog != null) errorLog.accept(msg + detail);
        if (infoLog != null) infoLog.accept(msg + detail);
    }

    private static void logStack(Consumer<String> log, String msg, Throwable t) {
        if (log == null) return;
        if (t == null) {
            log.accept(msg);
            return;
        }
        log.accept(msg + " :: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        StackTraceElement[] st = t.getStackTrace();
        int max = Math.min(st.length, 60);
        for (int i = 0; i < max; i++) {
            log.accept("    at " + st[i]);
        }
        Throwable cause = t.getCause();
        if (cause != null && cause != t) {
            log.accept("Caused by: " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
            StackTraceElement[] st2 = cause.getStackTrace();
            int max2 = Math.min(st2.length, 30);
            for (int i = 0; i < max2; i++) {
                log.accept("    at " + st2[i]);
            }
        }
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

    /**
     * Duplicatable body stream for OCI SDK body-signing paths.
     * The SDK may duplicate/read the body to compute x-content-sha256.
     */
    private static final class ByteArrayDuplicatableInputStream extends InputStream implements DuplicatableInputStream {
        private final byte[] bytes;
        private ByteArrayInputStream delegate;

        ByteArrayDuplicatableInputStream(byte[] bytes) {
            this.bytes = (bytes == null) ? new byte[0] : bytes;
            this.delegate = new ByteArrayInputStream(this.bytes);
        }

        @Override
        public int read() {
            return delegate.read();
        }

        @Override
        public int read(byte[] b, int off, int len) {
            return delegate.read(b, off, len);
        }

        @Override
        public int available() {
            return delegate.available();
        }

        @Override
        public synchronized void mark(int readlimit) {
            delegate.mark(readlimit);
        }

        @Override
        public synchronized void reset() throws IOException {
            delegate.reset();
        }

        @Override
        public boolean markSupported() {
            return delegate.markSupported();
        }

        @Override
        public long skip(long n) {
            return delegate.skip(n);
        }

        @Override
        public InputStream duplicate() {
            return new ByteArrayInputStream(bytes);
        }
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }
}
