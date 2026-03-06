package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.auth.OciX509SessionManager;
import com.webbinroot.ocisigner.keys.OciPrivateKeyCache;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.*;

/**
 * Signs requests using an OCI session token (keyId=ST$<token>) and a session private key.
 * This is used for manual Instance Principal federation workflows.
 */
public final class OciSessionTokenSigner {

    public static final class Result {
        public final Map<String, String> headersToApply;
        public final String signingString;
        public final String debugText;

        Result(Map<String, String> headersToApply, String signingString, String debugText) {
            // Example output: headersToApply contains Authorization + Date
            this.headersToApply = headersToApply;
            this.signingString = signingString;
            this.debugText = debugText;
        }
    }

    private OciSessionTokenSigner() {}

    public static Result sign(Profile profile,
                              OciX509SessionManager.SessionInfo session,
                              ManualSigningSettings settings,
                              String method,
                              String requestTarget,
                              String uriHost,
                              Map<String, List<String>> headersIn,
                              byte[] bodyBytes) {

        // Example input: session.token="<JWT>", method="GET", requestTarget="/n/"
        // Example output: Result.headersToApply contains Authorization (ST$ token)
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(session, "session");
        return sign(profile, session.token, session.sessionPrivateKey, settings,
                method, requestTarget, uriHost, headersIn, bodyBytes);
    }

    public static Result sign(Profile profile,
                              String token,
                              PrivateKey sessionPrivateKey,
                              ManualSigningSettings settings,
                              String method,
                              String requestTarget,
                              String uriHost,
                              Map<String, List<String>> headersIn,
                              byte[] bodyBytes) {

        // Example input: token="<JWT>", privateKey=<session key>, method="GET"
        Objects.requireNonNull(profile, "profile");
        if (settings == null) settings = ManualSigningSettings.defaultsLikeSdk();
        if (sessionPrivateKey == null) throw new IllegalArgumentException("Session private key is missing.");
        if (token == null || token.isBlank()) throw new IllegalArgumentException("Session token is missing.");

        // Example input:
        //   method=GET, requestTarget=/n/, host=objectstorage.us-phoenix-1.oraclecloud.com
        // Example output:
        //   Authorization: Signature keyId="ST$<token>" ...
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
                true,
                OciSigningCore.BodyHeaderPolicy.INCLUDE_PRESENT
        );

        String signatureB64 = signBase64(sessionPrivateKey, settings, prep.signingString);

        String keyId = "ST$" + token;
        String headersList = String.join(" ", prep.headersToSign);

        String authorization =
                "Signature " +
                        "version=\"1\"," +
                        "keyId=\"" + keyId + "\"," +
                        "algorithm=\"" + nz(settings.algorithm).toLowerCase(Locale.ROOT) + "\"," +
                        "headers=\"" + headersList + "\"," +
                        "signature=\"" + signatureB64 + "\"";

        Map<String, String> apply = new LinkedHashMap<>(prep.headersToApply);
        apply.put("authorization", authorization);

        String debug = buildDebug(prep.methodUpper, prep.requestTarget, prep.considerBody,
                prep.headersToSign, prep.headers, prep.signingString, authorization);

        return new Result(apply, prep.signingString, debug);
    }

    private static String buildDebug(String method,
                                     String requestTarget,
                                     boolean considerBody,
                                     List<String> headersToSign,
                                     Map<String, List<String>> headers,
                                     String signingString,
                                     String authorization) {
        StringBuilder sb = new StringBuilder();
        sb.append("method=").append(method).append("\n");
        sb.append("requestTarget=").append(requestTarget).append("\n");
        sb.append("considerBody=").append(considerBody).append("\n");
        sb.append("headersToSign=").append(String.join(" ", headersToSign)).append("\n");
        sb.append("signingString:\n").append(signingString).append("\n");
        sb.append("authorization:\n").append(authorization).append("\n");
        return sb.toString();
    }

    private static String signBase64(PrivateKey pk, ManualSigningSettings settings, String signingString) {
        try {
            String alg = nz(settings.algorithm).toLowerCase(Locale.ROOT);
            String sigAlg;
            switch (alg) {
                case "rsa-sha256" -> sigAlg = "SHA256withRSA";
                case "rsa-sha384" -> sigAlg = "SHA384withRSA";
                case "rsa-sha512" -> sigAlg = "SHA512withRSA";
                default -> throw new IllegalArgumentException("Session token signing only supports rsa-* algorithms.");
            }
            Signature s = Signature.getInstance(sigAlg);
            s.initSign(pk);
            s.update(signingString.getBytes(StandardCharsets.UTF_8));
            byte[] sig = s.sign();
            return Base64.getEncoder().encodeToString(sig);
        } catch (Exception e) {
            throw new IllegalArgumentException("Session token signing failed: " + e.getMessage(), e);
        }
    }

    public static PrivateKey loadPrivateKeyFromPem(String keyPath, String passphrase) {
        // Example input: "/home/kali/session_key.pem" -> PrivateKey
        String p = nz(keyPath);
        if (p.isBlank()) throw new IllegalArgumentException("Private key path is missing.");
        return OciPrivateKeyCache.loadRsaPrivateKey(p, passphrase);
    }


    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }
}
