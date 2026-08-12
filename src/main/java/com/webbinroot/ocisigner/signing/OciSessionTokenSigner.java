package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.util.OciTokenUtils;

import static com.webbinroot.ocisigner.util.OciTokenUtils.nz;

import java.security.PrivateKey;
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
                resolveDelegationToken(profile)
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

    /**
     * Resolve the profile's delegation (OBO) token, gated to Instance Principal only
     * (Oracle's SDKs only ship a dedicated delegation signer for instance principals).
     * This function is the single choke point for ALL session-token signing (live
     * signing, Test Credentials, Signature Calculator all funnel through it), so gating
     * here -- rather than at each of those call sites -- is what keeps a stray
     * Profile.delegationToken value from ever being applied to Resource Principal /
     * Security Token / Config Profile signing, without having to duplicate the same
     * auth-type check across every call site.
     */
    private static String resolveDelegationToken(Profile profile) {
        if (profile.authType() != AuthType.INSTANCE_PRINCIPAL) return null;
        String resolved = OciTokenUtils.resolveTokenValue(nz(profile.delegationToken));
        return resolved.isBlank() ? null : resolved;
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
            String sigAlg = OciSigningUtils.rsaJcaAlgorithm(alg);
            if (sigAlg == null) {
                throw new IllegalArgumentException("Session token signing only supports rsa-* algorithms.");
            }
            return OciSigningUtils.signRsaBase64(pk, sigAlg, signingString);
        } catch (Exception e) {
            throw new IllegalArgumentException("Session token signing failed: " + e.getMessage(), e);
        }
    }
}
