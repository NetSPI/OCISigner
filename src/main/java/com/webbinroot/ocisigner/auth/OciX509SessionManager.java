package com.webbinroot.ocisigner.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.bmc.auth.X509CertificateSupplier;
import com.webbinroot.ocisigner.keys.OciX509Suppliers;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.util.OciTokenUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Manual X.509 federation + session token cache.
 *
 * This is used when Instance Principal auth is configured with explicit
 * leaf cert/key inputs (non-IMDS environments). It generates a session
 * keypair, requests a security token, and caches the token + keypair
 * for signing subsequent requests.
 */
@SuppressWarnings("deprecation")
public final class OciX509SessionManager {

    public static final class SessionInfo {
        public final String token;
        public final long expEpochSec;
        public final PrivateKey sessionPrivateKey;
        public final PublicKey sessionPublicKey;
        public final long refreshedAtEpochSec;

        SessionInfo(String token,
                    long expEpochSec,
                    PrivateKey sessionPrivateKey,
                    PublicKey sessionPublicKey,
                    long refreshedAtEpochSec) {
            this.token = token;
            this.expEpochSec = expEpochSec;
            this.sessionPrivateKey = sessionPrivateKey;
            this.sessionPublicKey = sessionPublicKey;
            this.refreshedAtEpochSec = refreshedAtEpochSec;
        }
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ConcurrentHashMap<String, SessionInfo> CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, HttpClient> HTTP_CLIENT_CACHE = new ConcurrentHashMap<>();
    private static final CopyOnWriteArrayList<BiConsumer<Profile, SessionInfo>> LISTENERS = new CopyOnWriteArrayList<>();
    private static final long REFRESH_SKEW_SEC = 120;

    private OciX509SessionManager() {}

    /**
     * True if leaf cert + key inputs are present.
     * Example output: true when instanceX509LeafCert/key are set.
     */
    public static boolean hasInstanceX509Inputs(Profile p) {
        if (p == null) return false;
        return !isBlank(p.instanceX509LeafCert) && !isBlank(p.instanceX509LeafKey);
    }

    /**
     * Peek cached session token info (no refresh).
     */
    public static SessionInfo peek(Profile p) {
        if (p == null) return null;
        return CACHE.get(cacheKey(p));
    }

    /**
     * Return cached session token or refresh if expired/forced.
     * Example output: SessionInfo(token="<JWT>", expEpochSec=...)
     */
    public static SessionInfo getOrRefresh(Profile p,
                                           Consumer<String> infoLog,
                                           Consumer<String> errorLog,
                                           boolean forceRefresh) {
        if (p == null) return null;
        String key = cacheKey(p);
        SessionInfo existing = CACHE.get(key);
        if (!forceRefresh && existing != null && !isExpiredSoon(existing)) {
            cacheOnProfile(p, existing);
            return existing;
        }
        SessionInfo refreshed = refresh(p, infoLog, errorLog);
        if (refreshed != null) {
            CACHE.put(key, refreshed);
        }
        return refreshed;
    }

    /**
     * Force-refresh X509 session token using leaf cert/key.
     * Example output: SessionInfo(token="<JWT>", expEpochSec=...)
     */
    public static SessionInfo refresh(Profile p,
                                      Consumer<String> infoLog,
                                      Consumer<String> errorLog) {
        Objects.requireNonNull(p, "profile");
        logInfo(infoLog, "[OCI Signer][X509] Refreshing session token (manual federation)...");
        try {
            X509CertificateSupplier leaf = OciX509Suppliers.leafSupplier(
                    p.instanceX509LeafCert,
                    p.instanceX509LeafKey,
                    p.instanceX509LeafKeyPassphrase
            );
            X509Certificate leafCert = leaf.getCertificate();
            RSAPrivateKey leafKey = leaf.getPrivateKey();
            if (leafCert == null || leafKey == null) {
                throw new IllegalArgumentException("Leaf cert/key not available.");
            }

            List<X509CertificateSupplier> intermediates = OciX509Suppliers.intermediateSuppliers(
                    p.instanceX509IntermediateCerts
            );

            String tenancy = nz(p.instanceX509TenancyOcid);
            if (tenancy.isBlank()) {
                tenancy = tenancyFromCert(leafCert);
            }
            if (tenancy.isBlank()) {
                throw new IllegalArgumentException("Tenancy OCID missing (provide in UI or ensure cert contains opc-tenant).");
            }

            String endpoint = nz(p.instanceX509FederationEndpoint);
            if (endpoint.isBlank()) {
                endpoint = federationEndpointFromRegion(nz(p.region));
            }
            if (endpoint.isBlank()) {
                throw new IllegalArgumentException("Federation endpoint missing (provide endpoint or region).");
            }
            endpoint = normalizeFederationEndpoint(endpoint);

            KeyPair sessionKeys = generateSessionKeyPair();
            String token = requestSecurityToken(
                    endpoint,
                    tenancy,
                    leafCert,
                    leafKey,
                    sessionKeys.getPublic(),
                    intermediates,
                    p.federationProxyEnabled,
                    nz(p.federationProxyHost),
                    p.federationProxyPort,
                    p.federationInsecureTls,
                    infoLog
            );

            if (token == null || token.isBlank()) {
                throw new IllegalStateException("Federation response did not include a token.");
            }

            long exp = OciTokenUtils.extractJwtExp(token);
            if (exp <= 0) {
                // If exp is missing, refresh aggressively.
                exp = Instant.now().getEpochSecond() + 300;
            }

            SessionInfo info = new SessionInfo(
                    token,
                    exp,
                    sessionKeys.getPrivate(),
                    sessionKeys.getPublic(),
                    Instant.now().getEpochSecond()
            );

            logInfo(infoLog, "[OCI Signer][X509] Token refreshed; exp=" + exp);
            CACHE.put(cacheKey(p), info);
            cacheOnProfile(p, info);
            notifyListeners(p, info);
            return info;
        } catch (Exception e) {
            logError(errorLog, infoLog, "[OCI Signer][X509] Token refresh failed", e);
            return null;
        }
    }

    /**
     * Register a listener for token refresh events.
     */
    public static void addListener(BiConsumer<Profile, SessionInfo> listener) {
        if (listener != null) LISTENERS.add(listener);
    }

    /**
     * Remove a previously registered listener.
     */
    public static void removeListener(BiConsumer<Profile, SessionInfo> listener) {
        if (listener != null) LISTENERS.remove(listener);
    }

    private static void notifyListeners(Profile p, SessionInfo s) {
        for (BiConsumer<Profile, SessionInfo> l : LISTENERS) {
            try {
                l.accept(p, s);
            } catch (Exception ignored) {}
        }
    }

    private static void cacheOnProfile(Profile p, SessionInfo s) {
        if (p == null || s == null) return;
        try {
            p.cachedSessionToken = (s.token == null) ? "" : s.token;
            p.cachedSessionTokenExp = s.expEpochSec;
            p.cachedSessionTokenUpdatedAt = s.refreshedAtEpochSec;
        } catch (Exception ignored) {}
    }

    private static boolean isExpiredSoon(SessionInfo info) {
        if (info == null) return true;
        long now = Instant.now().getEpochSecond();
        return (info.expEpochSec - now) <= REFRESH_SKEW_SEC;
    }

    private static String requestSecurityToken(String endpoint,
                                               String tenancy,
                                               X509Certificate leafCert,
                                               RSAPrivateKey leafKey,
                                               PublicKey sessionPublicKey,
                                               List<X509CertificateSupplier> intermediates,
                                               boolean proxyEnabled,
                                               String proxyHost,
                                               int proxyPort,
                                               boolean insecureTls,
                                               Consumer<String> infoLog) throws Exception {
        // Example input:
        //   endpoint=https://auth.us-phoenix-1.oraclecloud.com
        // Example output (JSON body):
        //   { "token": "eyJraWQiOi..." }
        String url = endpoint + "/v1/x509";

        String body = buildX509Body(leafCert, intermediates, sessionPublicKey);
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);

        String date = DateTimeFormatter.RFC_1123_DATE_TIME.format(
                ZonedDateTime.now(java.time.ZoneOffset.UTC)
        );
        String contentSha256 = base64Sha256(bodyBytes);
        String requestTarget = "post /v1/x509";
        String signingString =
                "date: " + date + "\n" +
                        "(request-target): " + requestTarget + "\n" +
                        "content-length: " + bodyBytes.length + "\n" +
                        "content-type: application/json\n" +
                        "x-content-sha256: " + contentSha256;

        String keyId = tenancy + "/fed-x509/" + sha1Fingerprint(leafCert.getEncoded());
        String signature = signString(leafKey, signingString);

        String authHeader =
                "Signature algorithm=\"rsa-sha256\",headers=\"date (request-target) content-length content-type x-content-sha256\"," +
                        "keyId=\"" + keyId + "\",signature=\"" + signature + "\",version=\"1\"";

        HttpClient client = httpClient(proxyEnabled, proxyHost, proxyPort, insecureTls);
        HttpRequest.Builder rb = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("date", date)
                .header("content-type", "application/json")
                .header("x-content-sha256", contentSha256)
                .header("authorization", authHeader)
                .header("user-agent", "OCI-Signer/ManualFederation")
                .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes));

        HttpRequest req = rb.build();

        logInfo(infoLog, "[OCI Signer][X509] POST " + url + " (manual federation)");
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        logInfo(infoLog, "[OCI Signer][X509] Federation status=" + resp.statusCode());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IllegalArgumentException("Federation failed: HTTP " + resp.statusCode() + " body=" + truncate(resp.body(), 200));
        }

        return extractToken(resp.body());
    }

    private static HttpClient httpClient(boolean proxyEnabled,
                                         String proxyHost,
                                         int proxyPort,
                                         boolean insecureTls) {
        String host = nz(proxyHost);
        String key = (proxyEnabled ? ("proxy:" + host + ":" + proxyPort) : "direct")
                + "|tls:" + (insecureTls ? "insecure" : "default");
        return HTTP_CLIENT_CACHE.computeIfAbsent(key, k -> {
            HttpClient.Builder cb = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10));
            if (proxyEnabled && !isBlank(host) && proxyPort > 0) {
                cb.proxy(ProxySelector.of(new InetSocketAddress(host, proxyPort)));
            }
            if (insecureTls) {
                SSLContext sc = insecureSslContext();
                if (sc != null) cb.sslContext(sc);
            }
            return cb.build();
        });
    }

    private static String buildX509Body(X509Certificate leaf,
                                        List<X509CertificateSupplier> intermediates,
                                        PublicKey sessionPublicKey) throws Exception {
        String leafB64 = base64(leaf.getEncoded());
        String pubB64 = base64(sessionPublicKey.getEncoded());
        List<String> inter = new ArrayList<>();
        if (intermediates != null) {
            for (X509CertificateSupplier s : intermediates) {
                if (s == null || s.getCertificate() == null) continue;
                inter.add(base64(s.getCertificate().getEncoded()));
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"certificate\":\"").append(leafB64).append("\",");
        sb.append("\"publicKey\":\"").append(pubB64).append("\"");
        if (!inter.isEmpty()) {
            sb.append(",\"intermediateCertificates\":[");
            for (int i = 0; i < inter.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(inter.get(i)).append("\"");
            }
            sb.append("]");
        }
        sb.append("}");
        return sb.toString();
    }

    private static String extractToken(String body) {
        if (body == null) return "";
        try {
            JsonNode node = MAPPER.readTree(body);
            JsonNode token = node.get("token");
            if (token != null && token.isTextual()) {
                return token.asText();
            }
        } catch (Exception ignored) {}
        int idx = body.indexOf("\"token\"");
        if (idx < 0) return "";
        int colon = body.indexOf(":", idx);
        if (colon < 0) return "";
        int firstQuote = body.indexOf("\"", colon + 1);
        if (firstQuote < 0) return "";
        int secondQuote = body.indexOf("\"", firstQuote + 1);
        if (secondQuote < 0) return "";
        return body.substring(firstQuote + 1, secondQuote);
    }

    private static String tenancyFromCert(X509Certificate cert) {
        try {
            String subj = cert.getSubjectX500Principal().getName();
            String[] parts = subj.split(",");
            for (String p : parts) {
                String v = p.trim();
                if (v.startsWith("OU=opc-tenant:")) {
                    return v.substring("OU=opc-tenant:".length());
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static KeyPair generateSessionKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static String signString(PrivateKey key, String signingString) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key);
        sig.update(signingString.getBytes(StandardCharsets.UTF_8));
        return base64(sig.sign());
    }

    private static String base64Sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return base64(md.digest(data));
    }

    private static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static String sha1Fingerprint(byte[] der) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(der);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02X", digest[i]));
        }
        return sb.toString();
    }

    private static SSLContext insecureSslContext() {
        try {
            TrustManager[] trustAll = new TrustManager[] {
                    new X509TrustManager() {
                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[0];
                        }
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            return sc;
        } catch (Exception e) {
            return null;
        }
    }

    private static String federationEndpointFromRegion(String region) {
        String r = nz(region);
        if (r.isBlank()) return "";
        return "https://auth." + r + ".oraclecloud.com";
    }

    private static String normalizeFederationEndpoint(String endpoint) {
        String e = nz(endpoint);
        if (e.isBlank()) return e;
        try {
            URI uri = URI.create(e);
            String scheme = (uri.getScheme() == null || uri.getScheme().isBlank()) ? "https" : uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();
            if (host == null || host.isBlank()) return e;
            StringBuilder base = new StringBuilder();
            base.append(scheme).append("://").append(host);
            if (port > 0) base.append(":").append(port);
            return base.toString();
        } catch (Exception ignored) {
            return e;
        }
    }

    private static String cacheKey(Profile p) {
        StringBuilder sb = new StringBuilder();
        sb.append("IP|");
        sb.append(cachePart(p.instanceX509LeafCert)).append("|");
        sb.append(cachePart(p.instanceX509LeafKey)).append("|");
        sb.append(cachePart(p.instanceX509IntermediateCerts)).append("|");
        sb.append(nz(p.instanceX509FederationEndpoint)).append("|");
        sb.append(nz(p.instanceX509TenancyOcid)).append("|");
        sb.append(p.federationProxyEnabled).append("|");
        sb.append(nz(p.federationProxyHost)).append("|");
        sb.append(p.federationProxyPort).append("|");
        sb.append(p.federationInsecureTls);
        return sb.toString();
    }

    private static String cachePart(String s) {
        String v = nz(s);
        if (v.isBlank()) return "";
        return "hash:" + Integer.toHexString(v.hashCode()) + ":" + v.length();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }

    private static void logInfo(Consumer<String> log, String msg) {
        if (log != null && msg != null) log.accept(msg);
    }

    private static void logError(Consumer<String> errorLog, Consumer<String> infoLog, String msg, Throwable t) {
        String detail = (t == null) ? "" : (" :: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        if (errorLog != null) errorLog.accept(msg + detail);
        if (infoLog != null) infoLog.accept(msg + detail);
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String nz(String s) {
        return (s == null) ? "" : s.trim();
    }
}
