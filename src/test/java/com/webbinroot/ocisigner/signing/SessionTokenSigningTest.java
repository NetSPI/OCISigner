package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SessionTokenSigningTest {

    // SessionToken basic signing valid
    @Test
    void sessionToken_basic_signing_valid() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("session");

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers =
                TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        String token = "dummy.session.token";
        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                p, token, kp.getPrivate(), ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        String expectedSigningString = String.join("\n",
                "(request-target): get /20160918/regions",
                "date: " + TestUtils.FIXED_DATE,
                "host: identity.us-phoenix-1.oci.oraclecloud.com"
        );
        assertEquals(expectedSigningString, r.signingString);
        String expectedAuth = TestUtils.expectedSessionAuthorizationHeaderWithSig(
                "ST$" + token,
                "(request-target) date host",
                "rsa-sha256",
                TestUtils.SIG_SESSION_IDENTITY
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
        TestUtils.verifySignature(
                r.headersToApply.get("authorization"),
                r.signingString,
                kp.getPublic(),
                "rsa-sha256"
        );
    }

    // SessionToken missing token throws
    @Test
    void sessionToken_missing_token_throws() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("session");
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers =
                TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                OciSessionTokenSigner.sign(
                        p, "", kp.getPrivate(), ms, "GET", "/20160918/regions",
                        "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
                )
        );
        assertTrue(ex.getMessage().toLowerCase().contains("token"));
    }

    // SessionToken missing private key throws
    @Test
    void sessionToken_missing_private_key_throws() {
        Profile p = new Profile("session");
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers =
                TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                OciSessionTokenSigner.sign(
                        p, "abc.def.ghi", null, ms, "GET", "/20160918/regions",
                        "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
                )
        );
        assertTrue(ex.getMessage().toLowerCase().contains("private key"));
    }

    // Object Storage PUT signs present body headers (session token)
    @Test
    void sessionToken_objectStoragePut_signs_present_body_headers() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("session");

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers =
                TestUtils.baseHeaders("objectstorage.us-phoenix-1.oraclecloud.com");
        byte[] body = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        headers.put("content-type", List.of("application/octet-stream"));
        headers.put("content-length", List.of(String.valueOf(body.length)));
        headers.put("x-content-sha256", List.of(TestUtils.base64Sha256(body)));

        String token = "dummy.session.token";
        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                p, token, kp.getPrivate(), ms, "PUT", "/n/namespace/b/bucket/o/object",
                "objectstorage.us-phoenix-1.oraclecloud.com", headers, body
        );

        String xcs = TestUtils.base64Sha256(body);
        String expectedSigningString = String.join("\n",
                "(request-target): put /n/namespace/b/bucket/o/object",
                "date: " + TestUtils.FIXED_DATE,
                "host: objectstorage.us-phoenix-1.oraclecloud.com",
                "x-content-sha256: " + xcs,
                "content-type: application/octet-stream",
                "content-length: " + body.length
        );
        assertEquals(expectedSigningString, r.signingString);

        String expectedAuth = TestUtils.expectedSessionAuthorizationHeaderWithSig(
                "ST$" + token,
                "(request-target) date host x-content-sha256 content-type content-length",
                "rsa-sha256",
                TestUtils.SIG_API_OBJECTSTORAGE_PUT_WITH_BODY_HEADERS
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
        TestUtils.verifySignature(
                r.headersToApply.get("authorization"),
                r.signingString,
                kp.getPublic(),
                "rsa-sha256"
        );
    }
}
