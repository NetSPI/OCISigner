package com.webbinroot.ocisigner.auth;

import com.oracle.bmc.Region;
import com.oracle.bmc.auth.BasicAuthenticationDetailsProvider;
import com.oracle.bmc.auth.InstancePrincipalsAuthenticationDetailsProvider;
import com.oracle.bmc.auth.ResourcePrincipalAuthenticationDetailsProvider;
import com.oracle.bmc.auth.RefreshableOnNotAuthenticatedProvider;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
import com.oracle.bmc.auth.SessionTokenAuthenticationDetailsProvider;
import com.oracle.bmc.auth.SimpleAuthenticationDetailsProvider;
import com.oracle.bmc.auth.SimplePrivateKeySupplier;
import com.oracle.bmc.auth.X509CertificateSupplier;
import com.oracle.bmc.http.ClientConfigurator;
import com.oracle.bmc.http.client.ProxyConfiguration;
import com.oracle.bmc.http.client.StandardClientProperties;
import com.oracle.bmc.http.signing.DefaultRequestSigner;
import com.oracle.bmc.http.signing.RequestSigner;
import com.oracle.bmc.http.signing.SigningStrategy;
import com.oracle.bmc.ConfigFileReader;
import com.webbinroot.ocisigner.keys.OciX509Suppliers;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.signing.OciSessionTokenSigner;
import com.webbinroot.ocisigner.util.OciDebug;
import com.webbinroot.ocisigner.util.OciTokenUtils;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * OCI SDK crypto helpers.
 *
 * We intentionally rely on the OCI Java SDK signer for "Standard (OCI SDK)" mode.
 * Manual/custom signing is handled by OciRequestSigner and OciSignatureCalculator.
 */
public final class OciCrypto {

    private OciCrypto() {}

    private static final ConcurrentHashMap<String, RequestSigner> SIGNER_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, String> SESSION_TOKEN_HASH = new ConcurrentHashMap<>();
    /**
     * Build (or fetch cached) OCI SDK RequestSigner for a Profile.
     * Heavy operations must be amortized; this caching is critical to prevent Burp freezing.
     *
     * Example input:
     *  - AuthType.API_KEY profile + excludeBodyStrategy=false -> RequestSigner (SDK)
     */
    public static RequestSigner sdkSignerFor(Profile p, boolean excludeBodyStrategy) {
        Objects.requireNonNull(p, "profile");

        String key = signerCacheKey(p, excludeBodyStrategy);
        AuthType type = (p.authType() == null) ? AuthType.API_KEY : p.authType();

        if (type == AuthType.SECURITY_TOKEN) {
            String tokenHash = tokenHash(p.sessionToken);
            String cachedHash = SESSION_TOKEN_HASH.get(key);
            RequestSigner cached = SIGNER_CACHE.get(key);
            if (cached != null && Objects.equals(cachedHash, tokenHash)) {
                OciDebug.debug("[OCI Signer][Signer] Cache hit for key=" + key + " (session token)");
                return cached;
            }
            OciDebug.debug("[OCI Signer][Signer] Cache miss for key=" + key + " (session token)");
            return SIGNER_CACHE.compute(key, (k, existing) -> withContextClassLoader(() -> {
                OciDebug.debug("[OCI Signer][Signer] Creating RequestSigner...");
                BasicAuthenticationDetailsProvider provider = buildAuthProvider(p);
                SigningStrategy strategy = excludeBodyStrategy
                        ? SigningStrategy.EXCLUDE_BODY
                        : SigningStrategy.STANDARD;
                OciDebug.debug("[OCI Signer][Signer] Strategy=" + strategy);
                RequestSigner signer = DefaultRequestSigner.createRequestSigner(provider, strategy);
                OciDebug.debug("[OCI Signer][Signer] RequestSigner created: " + signer.getClass().getName());
                SESSION_TOKEN_HASH.put(k, tokenHash);
                return signer;
            }));
        }

        RequestSigner cached = SIGNER_CACHE.get(key);
        if (cached != null) {
            OciDebug.debug("[OCI Signer][Signer] Cache hit for key=" + key);
            return cached;
        }

        OciDebug.debug("[OCI Signer][Signer] Cache miss for key=" + key);
        return SIGNER_CACHE.computeIfAbsent(key, k -> withContextClassLoader(() -> {
            OciDebug.debug("[OCI Signer][Signer] Creating RequestSigner...");
            BasicAuthenticationDetailsProvider provider = buildAuthProvider(p);
            SigningStrategy strategy = excludeBodyStrategy
                    ? SigningStrategy.EXCLUDE_BODY
                    : SigningStrategy.STANDARD;
            OciDebug.debug("[OCI Signer][Signer] Strategy=" + strategy);
            RequestSigner signer = DefaultRequestSigner.createRequestSigner(provider, strategy);
            OciDebug.debug("[OCI Signer][Signer] RequestSigner created: " + signer.getClass().getName());
            return signer;
        }));
    }

    private static BasicAuthenticationDetailsProvider buildAuthProvider(Profile p) {
        AuthType type = (p.authType() == null) ? AuthType.API_KEY : p.authType();
        long startNs = System.nanoTime();
        OciDebug.debug("[OCI Signer][Federation] buildAuthProvider start type=" + type
                + " thread=" + Thread.currentThread().getName());
        logJvmInfoOnce();

        if (type == AuthType.INSTANCE_PRINCIPAL) {
            OciDebug.info("[OCI Signer][Federation] Building auth provider: Instance Principal");
            logClassInfo("com.oracle.bmc.auth.X509CertificateSupplier");
            logClassInfo("com.oracle.bmc.auth.X509CertificateSupplier$CertificateAndPrivateKeyPair");
            OciDebug.debug("[OCI Signer][Federation] TCCL=" + Thread.currentThread().getContextClassLoader());
            // Uses X.509 certificates from the OCI instance metadata service.
            InstancePrincipalsAuthenticationDetailsProvider.InstancePrincipalsAuthenticationDetailsProviderBuilder b =
                    InstancePrincipalsAuthenticationDetailsProvider.builder();
            b.federationClientConfigurator(federationTimeouts(p));

            if (hasInstanceX509Inputs(p)) {
                OciDebug.debug("[OCI Signer][Federation] Instance X509 inputs provided (leaf cert/key).");
                OciDebug.debug("[OCI Signer][Federation] LeafCert=" + describeSource(p.instanceX509LeafCert)
                        + " | LeafKey=" + describeSource(p.instanceX509LeafKey)
                        + " | IntermediateLines=" + countLines(p.instanceX509IntermediateCerts));
                X509CertificateSupplier leaf = OciX509Suppliers.leafSupplier(
                        p.instanceX509LeafCert,
                        p.instanceX509LeafKey,
                        p.instanceX509LeafKeyPassphrase
                );
                b.leafCertificateSupplier(leaf);

                // Optional intermediate cert chain
                var inter = OciX509Suppliers.intermediateSuppliers(p.instanceX509IntermediateCerts);
                if (!inter.isEmpty()) {
                    b.intermediateCertificateSuppliers(new HashSet<>(inter));
                }

                String federationEndpoint = nz(p.instanceX509FederationEndpoint);
                if (federationEndpoint.isBlank()) {
                    federationEndpoint = federationEndpointFromRegion(p.region);
                }
                if (federationEndpoint.isBlank()) {
                    throw new IllegalArgumentException("Instance principal X.509 requires a federation endpoint or region.");
                }
                federationEndpoint = normalizeFederationEndpoint(federationEndpoint);
                OciDebug.debug("[OCI Signer][Federation] Using federation endpoint: " + federationEndpoint);
                logProxySelector(federationEndpoint);
                b.federationEndpoint(federationEndpoint);

                String tenancyId = nz(p.instanceX509TenancyOcid);
                if (!tenancyId.isBlank()) {
                    OciDebug.debug("[OCI Signer][Federation] Using tenancy OCID override.");
                    b.tenancyId(tenancyId);
                } else {
                    OciDebug.debug("[OCI Signer][Federation] Tenancy OCID not provided (will rely on cert / environment).");
                }
            }

            BasicAuthenticationDetailsProvider out = b.build();
            long tookMs = (System.nanoTime() - startNs) / 1_000_000;
            OciDebug.info("[OCI Signer][Federation] Instance Principal provider built in " + tookMs + " ms");
            return out;
        }

        if (type == AuthType.RESOURCE_PRINCIPAL) {
            OciDebug.info("[OCI Signer][Federation] Building auth provider: Resource Principal");
            logClassInfo("com.oracle.bmc.auth.ResourcePrincipalAuthenticationDetailsProvider");
            // Uses resource principals / OBO, based on environment variables.
            boolean hasExplicit = hasResourcePrincipalInputs(p);
            if (hasExplicit) {
                String rpst = nz(p.resourcePrincipalRpst);
                String priv = nz(p.resourcePrincipalPrivateKey);
                String pass = nz(p.resourcePrincipalPrivateKeyPassphrase);
                if (pass.isBlank()) pass = null;
                String region = nz(p.region);

                if (rpst.isBlank() || priv.isBlank() || region.isBlank()) {
                    throw new IllegalArgumentException("Resource principal inputs require RPST, private key, and region.");
                }

                OciDebug.debug("[OCI Signer][Federation] RP explicit: rpst=" + describeSource(rpst)
                        + " | key=" + describeSource(priv)
                        + " | region=" + region
                        + " | passphraseLen=" + (pass == null ? 0 : pass.length()));
                OciDebug.debug("[OCI Signer][Federation] Resource principal explicit inputs provided (rpst/key/region).");
                // Use RP v2.2 flow with explicit values (token/key can be file path or raw content).
                return ResourcePrincipalAuthenticationDetailsProvider
                        .ResourcePrincipalAuthenticationDetailsProviderBuilder
                        .build_2_2(priv, pass, rpst, region, "provided value");
            }

            ResourcePrincipalAuthenticationDetailsProvider.ResourcePrincipalAuthenticationDetailsProviderBuilder b =
                    ResourcePrincipalAuthenticationDetailsProvider.builder();
            b.federationClientConfigurator(federationTimeouts(p));
            BasicAuthenticationDetailsProvider out = b.build();
            long tookMs = (System.nanoTime() - startNs) / 1_000_000;
            OciDebug.info("[OCI Signer][Federation] Resource Principal provider built in " + tookMs + " ms");
            return out;
        }

        if (type == AuthType.CONFIG_PROFILE) {
            OciDebug.info("[OCI Signer][Federation] Building auth provider: Config Profile (auto)");
            logClassInfo("com.oracle.bmc.auth.SessionTokenAuthenticationDetailsProvider");
            logClassInfo("com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider");
            try {
                OciConfigProfileResolver.ResolvedConfig resolved =
                        OciConfigProfileResolver.resolve(p);
                OciDebug.debug("[OCI Signer][Federation] Using config file: " + resolved.configPath
                        + " (profile: " + resolved.profileName + ")");
                ConfigFileReader.ConfigFile providerConfig =
                        configWithOptionalRegionOverride(
                                resolved.config,
                                resolved.profileName,
                                normalizeRegionId(nz(p.region))
                        );
                if (resolved.hasSecurityToken) {
                    BasicAuthenticationDetailsProvider out = new SessionTokenAuthenticationDetailsProvider(providerConfig);
                    long tookMs = (System.nanoTime() - startNs) / 1_000_000;
                    OciDebug.info("[OCI Signer][Federation] Config Profile detected security_token_file; using Session Token provider in " + tookMs + " ms");
                    return out;
                }

                BasicAuthenticationDetailsProvider out = new ConfigFileAuthenticationDetailsProvider(providerConfig);
                long tookMs = (System.nanoTime() - startNs) / 1_000_000;
                OciDebug.info("[OCI Signer][Federation] Config Profile using API Key provider in " + tookMs + " ms");
                return out;
            } catch (IOException e) {
                throw new IllegalArgumentException("Failed reading OCI config for Config Profile: " + e.getMessage(), e);
            }
        }

        if (type == AuthType.SECURITY_TOKEN) {
            OciDebug.info("[OCI Signer][Federation] Building auth provider: Session Token (direct)");
            logClassInfo("com.oracle.bmc.auth.SessionTokenAuthenticationDetailsProvider");
            String tenancy = nz(p.sessionTenancyOcid);
            String fingerprint = nz(p.sessionFingerprint);
            String keyFile = OciTokenUtils.expandHome(nz(p.sessionPrivateKeyPath));
            String passPhrase = nz(p.sessionPrivateKeyPassphrase);
            String tokenInput = nz(p.sessionToken);

            if (tenancy.isBlank() || fingerprint.isBlank()
                    || keyFile.isBlank() || tokenInput.isBlank()) {
                throw new IllegalArgumentException("Session token auth requires tenancy OCID, fingerprint, key file, and session token.");
            }

            try {
                Path tokenPath = Path.of(OciTokenUtils.expandHome(tokenInput));
                if (!Files.exists(tokenPath)) {
                    throw new IllegalArgumentException(
                            "Session token must be an existing file path when using SDK mode (in-memory tokens are signed manually)."
                    );
                }
                String tokenFile = tokenPath.toAbsolutePath().toString();
                String profileName = "DEFAULT";

                StringBuilder cfg = new StringBuilder();
                cfg.append("[").append(profileName).append("]\n");
                cfg.append("tenancy=").append(tenancy).append("\n");
                cfg.append("fingerprint=").append(fingerprint).append("\n");
                cfg.append("key_file=").append(keyFile).append("\n");
                if (!passPhrase.isBlank()) {
                    cfg.append("pass_phrase=").append(passPhrase).append("\n");
                }
                cfg.append("security_token_file=").append(tokenFile).append("\n");
                if (p.region != null && !p.region.isBlank()) {
                    cfg.append("region=").append(p.region.trim()).append("\n");
                }

                ConfigFileReader.ConfigFile config = ConfigFileReader.parse(
                        new ByteArrayInputStream(cfg.toString().getBytes(StandardCharsets.UTF_8)),
                        profileName
                );

                BasicAuthenticationDetailsProvider out = new SessionTokenAuthenticationDetailsProvider(config);
                long tookMs = (System.nanoTime() - startNs) / 1_000_000;
                OciDebug.info("[OCI Signer][Federation] Session Token provider built in " + tookMs + " ms");
                return out;
            } catch (IOException e) {
                throw new IllegalArgumentException("Failed building session token auth provider: " + e.getMessage(), e);
            }
        }

        OciDebug.info("[OCI Signer] Building auth provider: API Key");
        SimpleAuthenticationDetailsProvider.SimpleAuthenticationDetailsProviderBuilder b =
                SimpleAuthenticationDetailsProvider.builder()
                        .tenantId(nz(p.tenancyOcid))
                        .userId(nz(p.userOcid))
                        .fingerprint(nz(p.fingerprint))
                        .privateKeySupplier(new SimplePrivateKeySupplier(nz(p.privateKeyPath)));

        // Optional region (not required for signing, but harmless)
        try {
            if (p.region != null && !p.region.isBlank()) {
                b.region(Region.fromRegionId(p.region.trim()));
            }
        } catch (Exception ignored) {
            // If invalid region string, don't fail provider creation.
        }

        // NOTE: SDK mode ignores encrypted private key passphrases.
        // If user provides passphrase, we still let them save it for future manual mode.

        BasicAuthenticationDetailsProvider out = b.build();
        long tookMs = (System.nanoTime() - startNs) / 1_000_000;
        OciDebug.info("[OCI Signer] API Key provider built in " + tookMs + " ms");
        return out;
    }

    /**
     * Test credentials by attempting a token refresh when supported.
     * Returns a human-readable result (never null).
     *
     * Example:
     *  - API Key profile -> "OK (no refresh available)"
     *  - Instance Principal (manual X509) -> "OK (token length: 2220; namespace HTTP 200)"
     */
    public static String testCredentials(Profile p) {
        return withContextClassLoader(() -> {
            OciDebug.info("[OCI Signer][Test] Starting credential test for profile: " + (p == null ? "null" : p.name()));
            if (p != null) {
                OciDebug.info("[OCI Signer][Test] AuthType=" + p.authType()
                        + " | Region=" + nz(p.region)
                        + " | FederationEndpoint=" + nz(p.instanceX509FederationEndpoint)
                        + " | Proxy=" + (p.federationProxyEnabled ? "on" : "off") + " " + nz(p.federationProxyHost) + ":" + p.federationProxyPort);
            }

            // Manual X509 session token refresh (for non-IMDS instance principal inputs).
            if (p != null && p.authType() == AuthType.INSTANCE_PRINCIPAL
                    && OciX509SessionManager.hasInstanceX509Inputs(p)) {
                String provided = nz(p.cachedSessionToken);
                if (!provided.isBlank()) {
                    OciDebug.info("[OCI Signer][Test] Using provided instance session token for namespace test.");
                    String token = OciTokenUtils.resolveTokenValue(provided);
                    OciX509SessionManager.SessionInfo cached = OciX509SessionManager.peek(p);
                    if (cached == null || cached.sessionPrivateKey == null) {
                        return "FAILED (session token provided but no cached session private key; click Refresh Token)";
                    }
                    return testNamespaceWithSessionToken(p, token, cached.sessionPrivateKey);
                }

                OciDebug.info("[OCI Signer][Test] Using manual X509 federation (session token).");
                OciX509SessionManager.SessionInfo s = OciX509SessionManager.refresh(p, OciDebug::info, OciDebug::info);
                if (s == null || s.token == null || s.sessionPrivateKey == null) {
                    return "FAILED (manual X509 token refresh failed)";
                }
                return testNamespaceWithSessionToken(p, s.token, s.sessionPrivateKey);
            }

            // Manual Resource Principal token (explicit RPST + key)
            if (p != null && p.authType() == AuthType.RESOURCE_PRINCIPAL
                    && OciRpstSessionManager.hasExplicitInputs(p)) {
                OciDebug.info("[OCI Signer][Test] Using manual RPST (resource principal).");
                OciX509SessionManager.SessionInfo s =
                        OciRpstSessionManager.getOrRefresh(p, OciDebug::info, OciDebug::info, false);
                if (s == null || s.token == null) {
                    return "FAILED (RPST token load failed)";
                }

                return testNamespaceWithSessionToken(p, s.token, s.sessionPrivateKey);
            }

            // Security Token (direct): validate token + private key without disk writes.
            if (p != null && p.authType() == AuthType.SECURITY_TOKEN) {
                OciDebug.info("[OCI Signer][Test] Using session token (direct) in-memory.");
                OciSessionTokenResolver.Material material =
                        OciSessionTokenResolver.fromSecurityToken(p, OciDebug::info, OciDebug::info);
                if (material == null || material.token == null || material.privateKey == null) {
                    return "FAILED (session token or private key missing)";
                }
                return "OK (token length: " + material.token.length() + ")";
            }

            BasicAuthenticationDetailsProvider provider = buildAuthProvider(p);
            OciDebug.debug("[OCI Signer][Test] Provider class: " + provider.getClass().getName());
            if (provider instanceof RefreshableOnNotAuthenticatedProvider<?> refreshable) {
                OciDebug.info("[OCI Signer][Test] Refreshable provider detected; attempting refresh...");
                Object token = refreshable.refresh();
                if (token == null) return "OK (refresh returned null)";
                String t = token.toString();
                int len = t.length();
                OciDebug.info("[OCI Signer][Test] Refresh succeeded; token length=" + len);
                return "OK (token length: " + len + ")";
            }
            OciDebug.info("[OCI Signer][Test] Provider not refreshable.");
            return "OK (no refresh available)";
        });
    }

    private static String nz(String s) {
        return (s == null) ? "" : s.trim();
    }

    private static String tokenHash(String tokenOrPath) {
        String token = OciTokenUtils.resolveTokenValue(tokenOrPath);
        if (token == null || token.isBlank()) return "";
        return Integer.toHexString(token.hashCode()) + ":" + token.length();
    }

    private static String testNamespaceWithSessionToken(Profile p, String token, java.security.PrivateKey privateKey) {
        if (token == null || token.isBlank() || privateKey == null) {
            return "FAILED (session token or private key missing)";
        }
        String region = nz(p == null ? "" : p.region);
        region = normalizeRegionId(region);
        if (region.isBlank()) {
            return "OK (token length: " + token.length() + "; no region set for namespace test)";
        }

        try {
            String endpoint = "https://objectstorage." + region + ".oraclecloud.com/n/";
            HttpRequest.Builder b = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .timeout(Duration.ofSeconds(15))
                    .GET();

            OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                    p,
                    token,
                    privateKey,
                    ManualSigningSettings.defaultsLikeSdk(),
                    "GET",
                    "/n/",
                    URI.create(endpoint).getHost(),
                    new java.util.LinkedHashMap<>(),
                    null
            );
            for (var e : r.headersToApply.entrySet()) {
                String name = e.getKey();
                if (name == null) continue;
                String lower = name.toLowerCase();
                // Java HttpClient forbids setting certain headers (e.g., Host, Content-Length).
                if ("host".equals(lower) || "content-length".equals(lower)) {
                    continue;
                }
                b.header(name, e.getValue());
            }
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
            HttpResponse<String> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
            return "OK (token length: " + token.length() + "; namespace HTTP " + resp.statusCode() + ")";
        } catch (Exception e) {
            return "OK (token length: " + token.length() + "; namespace test failed: " + e.getMessage() + ")";
        }
    }


    private static String signerCacheKey(Profile p, boolean excludeBodyStrategy) {
        AuthType type = (p.authType() == null) ? AuthType.API_KEY : p.authType();
        String base = type.name();

        if (type == AuthType.SECURITY_TOKEN) {
            return String.join("|",
                    base,
                    nz(p.sessionTenancyOcid),
                    nz(p.sessionFingerprint),
                    nz(p.sessionPrivateKeyPath),
                    String.valueOf(excludeBodyStrategy)
            );
        }

        if (type == AuthType.CONFIG_PROFILE) {
            return String.join("|",
                    base,
                    nz(p.configFilePath),
                    nz(p.configProfileName),
                    normalizeRegionId(nz(p.region)),
                    String.valueOf(excludeBodyStrategy)
            );
        }

        if (type == AuthType.INSTANCE_PRINCIPAL || type == AuthType.RESOURCE_PRINCIPAL) {
            String fed = nz(p.instanceX509FederationEndpoint);
            if (fed.isBlank()) fed = federationEndpointFromRegion(p.region);
            fed = normalizeFederationEndpoint(fed);
            String key = String.join("|",
                    base,
                    cachePart(p.instanceX509LeafCert),
                    cachePart(p.instanceX509LeafKey),
                    cachePart(p.instanceX509IntermediateCerts),
                    nz(fed),
                    nz(p.instanceX509TenancyOcid),
                    String.valueOf(p.federationProxyEnabled),
                    nz(p.federationProxyHost),
                    String.valueOf(p.federationProxyPort),
                    cachePart(p.resourcePrincipalRpst),
                    cachePart(p.resourcePrincipalPrivateKey),
                    nz(p.region),
                    String.valueOf(excludeBodyStrategy)
            );
            OciDebug.debug("[OCI Signer][Signer] CacheKey(IP/RP)=" + key);
            return key;
        }

        // API key
        String key = String.join("|",
                base,
                nz(p.tenancyOcid),
                nz(p.userOcid),
                nz(p.fingerprint),
                nz(p.privateKeyPath),
                String.valueOf(excludeBodyStrategy)
        );
        OciDebug.debug("[OCI Signer][Signer] CacheKey(API)=" + key);
        return key;
    }

    private static boolean hasInstanceX509Inputs(Profile p) {
        return !(nz(p.instanceX509LeafCert).isBlank() && nz(p.instanceX509LeafKey).isBlank());
    }

    private static boolean hasResourcePrincipalInputs(Profile p) {
        return !(nz(p.resourcePrincipalRpst).isBlank() && nz(p.resourcePrincipalPrivateKey).isBlank());
    }

    private static String federationEndpointFromRegion(String region) {
        String r = nz(region);
        if (r.isBlank()) return "";
        // Java SDK expects the AUTH service base endpoint (no /v1/x509 in the base).
        return "https://auth." + r + ".oraclecloud.com";
    }

    private static String normalizeFederationEndpoint(String endpoint) {
        String e = nz(endpoint);
        if (e.isBlank()) return e;
        try {
            java.net.URI uri = java.net.URI.create(e);
            String scheme = (uri.getScheme() == null || uri.getScheme().isBlank()) ? "https" : uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();
            if (host == null || host.isBlank()) return e;

            StringBuilder base = new StringBuilder();
            base.append(scheme).append("://").append(host);
            if (port > 0) base.append(":").append(port);

            String path = uri.getPath();
            if (path != null && !path.isBlank() && !"/".equals(path)) {
                OciDebug.debug("[OCI Signer][Federation] Normalized endpoint (strip path '" + path + "') -> " + base);
            }
            return base.toString();
        } catch (Exception ignored) {
            // If URI parsing fails, avoid changing user input.
            return e;
        }
    }

    private static ConfigFileReader.ConfigFile configWithOptionalRegionOverride(ConfigFileReader.ConfigFile src,
                                                                                 String profileName,
                                                                                 String regionOverride) throws IOException {
        String profile = nz(profileName);
        if (profile.isBlank()) profile = "DEFAULT";

        String region = normalizeRegionId(nz(regionOverride));
        if (region.isBlank()) {
            region = normalizeRegionId(nz(src == null ? "" : src.get("region")));
        }

        StringBuilder cfg = new StringBuilder();
        cfg.append("[").append(profile).append("]\n");
        appendCfgEntry(cfg, "tenancy", src == null ? "" : src.get("tenancy"));
        appendCfgEntry(cfg, "user", src == null ? "" : src.get("user"));
        appendCfgEntry(cfg, "fingerprint", src == null ? "" : src.get("fingerprint"));
        appendCfgEntry(cfg, "key_file", src == null ? "" : src.get("key_file"));
        appendCfgEntry(cfg, "pass_phrase", src == null ? "" : src.get("pass_phrase"));
        appendCfgEntry(cfg, "security_token_file", src == null ? "" : src.get("security_token_file"));
        appendCfgEntry(cfg, "region", region);

        return ConfigFileReader.parse(
                new ByteArrayInputStream(cfg.toString().getBytes(StandardCharsets.UTF_8)),
                profile
        );
    }

    private static void appendCfgEntry(StringBuilder cfg, String key, String value) {
        String v = nz(value);
        if (v.isBlank()) return;
        cfg.append(key).append("=").append(v).append("\n");
    }

    private static String normalizeRegionId(String region) {
        String v = nz(region);
        if (v.isBlank()) return "";
        return v.toLowerCase(Locale.ROOT);
    }

    private static String cachePart(String s) {
        String v = nz(s);
        if (v.isBlank()) return "";
        if (looksLikePath(v)) {
            return "path:" + v;
        }
        return "hash:" + Integer.toHexString(v.hashCode()) + ":" + v.length();
    }

    private static boolean looksLikePath(String v) {
        try {
            Path p = Path.of(v);
            return Files.exists(p);
        } catch (Exception ignored) {
            return false;
        }
    }

    private static <T> T withContextClassLoader(Supplier<T> fn) {
        Thread t = Thread.currentThread();
        ClassLoader prev = t.getContextClassLoader();
        ClassLoader cl = OciCrypto.class.getClassLoader();
        try {
            t.setContextClassLoader(cl);
            return fn.get();
        } finally {
            t.setContextClassLoader(prev);
        }
    }

    private static ClientConfigurator federationTimeouts(Profile p) {
        return builder -> {
            OciDebug.debug("[OCI Signer][Federation] HttpClientBuilder=" + builder.getClass().getName());
            // Keep federation calls from hanging Burp's request thread.
            builder.property(StandardClientProperties.CONNECT_TIMEOUT, Duration.ofSeconds(15));
            builder.property(StandardClientProperties.READ_TIMEOUT, Duration.ofSeconds(15));
            OciDebug.debug("[OCI Signer][Federation] Timeouts set: connect/read = 15s");

            // Note: HttpClientBuilder here is not a JAX-RS client and does not support register().
            // We rely on higher-level debug logs for now.

            if (p != null && p.federationProxyEnabled) {
                String host = nz(p.federationProxyHost);
                int port = p.federationProxyPort;
                if (!host.isBlank() && port > 0) {
                    java.net.Proxy proxy = new java.net.Proxy(
                            java.net.Proxy.Type.HTTP,
                            new java.net.InetSocketAddress(host, port)
                    );
                    builder.property(StandardClientProperties.PROXY,
                            ProxyConfiguration.builder().proxy(proxy).build());
                    OciDebug.debug("[OCI Signer][Federation] PROXY property set on HttpClientBuilder");
                    OciDebug.info("[OCI Signer][Federation] Proxy enabled for federation: " + host + ":" + port);
                } else {
                    OciDebug.info("[OCI Signer][Federation] Proxy enabled but host/port invalid.");
                }
            } else {
                OciDebug.debug("[OCI Signer][Federation] Proxy disabled for federation.");
            }

            if (p != null && p.federationInsecureTls) {
                SSLContext ctx = insecureSslContext();
                if (ctx != null) {
                    builder.property(StandardClientProperties.SSL_CONTEXT, ctx);
                    OciDebug.info("[OCI Signer][Federation] Insecure TLS enabled (trust all).");
                }
            }
        };
    }

    private static void logJvmInfoOnce() {
        // Emit once per run (best-effort).
        if (JvmInfoHolder.logged) return;
        JvmInfoHolder.logged = true;
        OciDebug.info("[OCI Signer][JVM] java.version=" + System.getProperty("java.version")
                + " | java.vendor=" + System.getProperty("java.vendor")
                + " | java.home=" + System.getProperty("java.home"));
        OciDebug.info("[OCI Signer][JVM] os.name=" + System.getProperty("os.name")
                + " | os.arch=" + System.getProperty("os.arch")
                + " | os.version=" + System.getProperty("os.version"));
        OciDebug.info("[OCI Signer][JVM] trustStore=" + System.getProperty("javax.net.ssl.trustStore")
                + " | trustStoreType=" + System.getProperty("javax.net.ssl.trustStoreType"));
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
            OciDebug.logStack("[OCI Signer][Federation] Failed to init insecure SSL context", e);
            return null;
        }
    }

    private static final class JvmInfoHolder {
        static boolean logged = false;
    }

    private static String describeSource(String source) {
        if (source == null) return "(null)";
        String s = source.trim();
        if (s.isEmpty()) return "(empty)";
        if (s.contains("-----BEGIN")) return "inline PEM (len=" + s.length() + ")";
        try {
            Path p = Path.of(s);
            if (Files.isRegularFile(p)) {
                long size = Files.size(p);
                return "file:" + p + " (bytes=" + size + ")";
            }
        } catch (Exception ignored) {}
        return "raw text (len=" + s.length() + ")";
    }

    private static int countLines(String s) {
        if (s == null || s.isBlank()) return 0;
        return s.split("\\r?\\n").length;
    }

    private static void logClassInfo(String className) {
        try {
            ClassLoader cl = OciCrypto.class.getClassLoader();
            Class<?> c = Class.forName(className, false, cl);
            String src = (c.getProtectionDomain() != null && c.getProtectionDomain().getCodeSource() != null)
                    ? String.valueOf(c.getProtectionDomain().getCodeSource().getLocation())
                    : "unknown";
            OciDebug.debug("[OCI Signer][ClassLoader] " + className
                    + " loaded by " + String.valueOf(c.getClassLoader())
                    + " from " + src);
        } catch (Throwable t) {
            OciDebug.logStack("[OCI Signer][ClassLoader] Failed loading " + className, t);
        }
    }

    private static void logProxySelector(String endpoint) {
        try {
            java.net.URI uri = java.net.URI.create(endpoint);
            java.net.ProxySelector sel = java.net.ProxySelector.getDefault();
            if (sel == null) {
                OciDebug.debug("[OCI Signer][Federation] ProxySelector: null");
                return;
            }
            List<java.net.Proxy> proxies = sel.select(uri);
            OciDebug.debug("[OCI Signer][Federation] ProxySelector for " + endpoint + " -> " + proxies);
        } catch (Exception e) {
            OciDebug.logStack("[OCI Signer][Federation] ProxySelector error", e);
        }
    }
}
