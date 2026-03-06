package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.keys.OciPrivateKeyCache;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.*;

public final class OciManualSigner {

    public static final class Result {
        public final Map<String, String> headersToApply;
        public final String signingString;
        public final String debugText;

        public Result(Map<String, String> headersToApply, String signingString, String debugText) {
            // Example output: headersToApply includes "authorization" and "date"
            this.headersToApply = headersToApply;
            this.signingString = signingString;
            this.debugText = debugText;
        }
    }

    private OciManualSigner() {}

    public static Result sign(Profile profile,
                              ManualSigningSettings settings,
                              String method,
                              String requestTarget,
                              String uriHost,
                              Map<String, List<String>> headersIn,
                              byte[] bodyBytes) {

        Objects.requireNonNull(profile, "profile");
        if (settings == null) settings = ManualSigningSettings.defaultsLikeSdk();

        // Example input:
        //   method=GET, requestTarget=/n/, headersIn={"host":["objectstorage..."]}
        // Example output:
        //   Authorization: Signature keyId="<tenancy>/<user>/<fingerprint>" ...
        boolean objectStoragePutSpecial =
                OciSigningUtils.isObjectStoragePutSpecial(method, uriHost, requestTarget);
        OciSigningCore.Prepared prep = OciSigningCore.prepare(
                settings,
                method,
                requestTarget,
                uriHost,
                headersIn,
                bodyBytes,
                objectStoragePutSpecial,
                false,
                OciSigningCore.BodyHeaderPolicy.INCLUDE_PRESENT
        );

        String alg = nz(settings.algorithm).toLowerCase(Locale.ROOT);
        String signatureB64 = signBase64(profile, settings, alg, prep.signingString);

        String keyId = nz(profile.tenancyOcid) + "/" + nz(profile.userOcid) + "/" + nz(profile.fingerprint);
        String headersList = String.join(" ", prep.headersToSign);

        String authorization =
                "Signature " +
                        "version=\"1\"," +
                        "keyId=\"" + keyId + "\"," +
                        "algorithm=\"" + alg + "\"," +
                        "headers=\"" + headersList + "\"," +
                        "signature=\"" + signatureB64 + "\"";

        Map<String, String> apply = new LinkedHashMap<>(prep.headersToApply);
        apply.put("authorization", authorization);

        String debug = buildDebug(profile, settings, prep.methodUpper, prep.requestTarget,
                prep.considerBody, objectStoragePutSpecial, prep.headersToSign, prep.headers, prep.signingString, authorization);

        return new Result(apply, prep.signingString, debug);
    }

    private static String signBase64(Profile profile,
                                     ManualSigningSettings settings,
                                     String algorithm,
                                     String signingString) {

        // RSA modes
        if (algorithm.startsWith("rsa-")) {
            String sigAlg;
            switch (algorithm) {
                case "rsa-sha256" -> sigAlg = "SHA256withRSA";
                case "rsa-sha384" -> sigAlg = "SHA384withRSA";
                case "rsa-sha512" -> sigAlg = "SHA512withRSA";
                default -> throw new IllegalArgumentException("Unsupported RSA manual algorithm: " + algorithm);
            }

            PrivateKey pk = loadPrivateKeyCached(profile);

            try {
                Signature s = Signature.getInstance(sigAlg);
                s.initSign(pk);
                s.update(signingString.getBytes(StandardCharsets.UTF_8));
                byte[] sig = s.sign();
                return Base64.getEncoder().encodeToString(sig);
            } catch (Exception e) {
                throw new IllegalArgumentException("Manual RSA signing failed: " + e.getMessage(), e);
            }
        }

        // HMAC modes
        if (algorithm.startsWith("hmac-")) {
            String macAlg;
            switch (algorithm) {
                case "hmac-sha256" -> macAlg = "HmacSHA256";
                case "hmac-sha384" -> macAlg = "HmacSHA384";
                case "hmac-sha512" -> macAlg = "HmacSHA512";
                default -> throw new IllegalArgumentException("Unsupported HMAC manual algorithm: " + algorithm);
            }

            byte[] keyBytes = resolveHmacKeyBytes(settings);
            if (keyBytes == null || keyBytes.length == 0) {
                throw new IllegalArgumentException("HMAC algorithm selected but HMAC key is missing.");
            }

            try {
                Mac mac = Mac.getInstance(macAlg);
                mac.init(new SecretKeySpec(keyBytes, macAlg));
                byte[] out = mac.doFinal(signingString.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(out);
            } catch (Exception e) {
                throw new IllegalArgumentException("Manual HMAC signing failed: " + e.getMessage(), e);
            }
        }

        // UI options we haven't implemented yet
        throw new IllegalArgumentException("Unsupported manual algorithm (not implemented yet): " + algorithm);
    }

    private static byte[] resolveHmacKeyBytes(ManualSigningSettings settings) {
        if (settings.hmacKeyMode == ManualSigningSettings.HmacKeyMode.FILE) {
            String p = (settings.hmacKeyFilePath == null) ? "" : settings.hmacKeyFilePath.trim();
            if (p.isEmpty()) return null;

            try {
                byte[] raw = Files.readAllBytes(Path.of(p));

                // If the file looks like "base64:...." treat it as base64 text
                String asText = new String(raw, StandardCharsets.UTF_8).trim();
                if (asText.regionMatches(true, 0, "base64:", 0, "base64:".length())) {
                    return ManualSigningSettings.parseHmacKeyText(asText);
                }

                // otherwise treat as raw bytes
                return raw;
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed reading HMAC key file: " + e.getMessage(), e);
            }
        }

        // TEXT mode
        return ManualSigningSettings.parseHmacKeyText(settings.hmacKeyText);
    }

    private static PrivateKey loadPrivateKeyCached(Profile profile) {
        String keyPath = nz(profile.privateKeyPath);
        if (keyPath.isBlank()) throw new IllegalArgumentException("Private key path is missing.");
        return OciPrivateKeyCache.loadRsaPrivateKey(keyPath, nz(profile.privateKeyPassphrase));
    }

    private static String buildDebug(Profile profile,
                                     ManualSigningSettings settings,
                                     String methodUpper,
                                     String requestTarget,
                                     boolean considerBody,
                                     boolean objectStoragePutSpecial,
                                     List<String> headersToSign,
                                     Map<String, List<String>> headers,
                                     String signingString,
                                     String authorizationValue) {

        StringBuilder sb = new StringBuilder();
        sb.append("=== OCI Manual Signer ===\n\n");

        sb.append("Profile:\n");
        sb.append("  tenancy:     ").append(nz(profile.tenancyOcid)).append("\n");
        sb.append("  user:        ").append(nz(profile.userOcid)).append("\n");
        sb.append("  fingerprint: ").append(nz(profile.fingerprint)).append("\n");
        sb.append("  key_file:    ").append(nz(profile.privateKeyPath)).append("\n\n");

        sb.append("Settings:\n");
        sb.append("  algorithm: ").append(nz(settings.algorithm)).append("\n");
        sb.append("  objectStoragePutSpecial: ").append(objectStoragePutSpecial).append("\n");
        sb.append("  considerBody: ").append(considerBody).append("\n");
        sb.append("  headers: ").append(String.join(" ", headersToSign)).append("\n");
        if (settings.isHmacAlgorithm()) {
            sb.append("  hmacKeyMode: ").append(settings.hmacKeyMode).append("\n");
        }
        sb.append("\n");

        sb.append("Request:\n");
        sb.append("  method: ").append(methodUpper).append("\n");
        sb.append("  request-target: ").append(requestTarget).append("\n\n");

        sb.append("Headers (post-derivation):\n");
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            sb.append("  ").append(e.getKey()).append(": ").append(String.join(", ", e.getValue())).append("\n");
        }

        sb.append("\nSigning String:\n");
        sb.append(signingString).append("\n\n");

        sb.append("Authorization (value):\n");
        sb.append(authorizationValue).append("\n");

        return sb.toString();
    }

    private static String nz(String s) {
        return (s == null) ? "" : s.trim();
    }
}
