package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ApiKeySigningTest {

    // Get noBody signingString and signature valid
    @Test
    void get_noBody_signingString_and_signature_valid() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "11:22:33:44:55:66:77";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = TestUtils.baseHeaders("objectstorage.us-phoenix-1.oraclecloud.com");

        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "GET", "/n/namespace",
                "objectstorage.us-phoenix-1.oraclecloud.com", headers, null
        );

        String expectedSigningString = String.join("\n",
                "(request-target): get /n/namespace",
                "date: " + TestUtils.FIXED_DATE,
                "host: objectstorage.us-phoenix-1.oraclecloud.com"
        );
        assertEquals(expectedSigningString, r.signingString);

        String auth = r.headersToApply.get("authorization");
        assertNotNull(auth);
        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host",
                "rsa-sha256",
                TestUtils.SIG_API_GET
        );
        assertEquals(expectedAuth, auth);
        TestUtils.verifySignature(auth, r.signingString, kp.getPublic(), "rsa-sha256");
    }

    // Post withBody addsBodyHeaders and signature valid
    @Test
    void post_withBody_addsBodyHeaders_and_signature_valid() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "aa:bb:cc:dd:ee";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("identity.us-phoenix-1.oci.oraclecloud.com"));
        headers.put("date", List.of(TestUtils.FIXED_DATE));
        headers.put("content-type", List.of("application/json"));

        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "POST", "/20160918/compartments",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, body
        );

        String xcs = TestUtils.base64Sha256(body);
        String cl = String.valueOf(body.length);

        assertEquals(xcs, r.headersToApply.get("x-content-sha256"));
        assertEquals(cl, r.headersToApply.get("content-length"));

        String expectedSigningString = String.join("\n",
                "(request-target): post /20160918/compartments",
                "date: " + TestUtils.FIXED_DATE,
                "host: identity.us-phoenix-1.oci.oraclecloud.com",
                "x-content-sha256: " + xcs,
                "content-type: application/json",
                "content-length: " + cl
        );
        assertEquals(expectedSigningString, r.signingString);

        String auth = r.headersToApply.get("authorization");
        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host x-content-sha256 content-type content-length",
                "rsa-sha256",
                TestUtils.SIG_API_POST
        );
        assertEquals(expectedAuth, auth);
        TestUtils.verifySignature(auth, r.signingString, kp.getPublic(), "rsa-sha256");
    }

    // Get withBody disallowed ignores body headers
    @Test
    void get_withBody_disallowed_ignores_body_headers() throws Exception {
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "ff:ee:dd:cc:bb";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");
        headers.put("content-type", List.of("application/json"));

        byte[] body = "{\"x\":1}".getBytes(StandardCharsets.UTF_8);
        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, body
        );

        assertFalse(r.signingString.contains("x-content-sha256"));
        assertFalse(r.signingString.contains("content-length"));
        assertNull(r.headersToApply.get("x-content-sha256"));
        assertNull(r.headersToApply.get("content-length"));
    }

    // Extra headers are included in signing string
    @Test
    void extra_headers_are_included_in_signing_string() throws Exception {
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "12:34:56";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        ms.extraSignedHeaders = "opc-request-id\nx-custom";

        Map<String, List<String>> headers = TestUtils.baseHeaders("objectstorage.us-phoenix-1.oraclecloud.com");
        headers.put("opc-request-id", List.of("req-123"));
        headers.put("x-custom", List.of("abc"));

        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "GET", "/n/namespace",
                "objectstorage.us-phoenix-1.oraclecloud.com", headers, null
        );

        String expected = String.join("\n",
                "(request-target): get /n/namespace",
                "date: " + TestUtils.FIXED_DATE,
                "host: objectstorage.us-phoenix-1.oraclecloud.com",
                "opc-request-id: req-123",
                "x-custom: abc"
        );
        assertEquals(expected, r.signingString);
        String auth = r.headersToApply.get("authorization");
        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host opc-request-id x-custom",
                "rsa-sha256",
                TestUtils.SIG_API_EXTRA
        );
        assertEquals(expectedAuth, auth);
    }

    // Disable date removes date from signing string
    @Test
    void disable_date_removes_date_from_signing_string() throws Exception {
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "de:ad:be:ef";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        ms.signDate = false;
        ms.addMissingDate = false;

        Map<String, List<String>> headers = TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        String expectedSigningString = String.join("\n",
                "(request-target): get /20160918/regions",
                "host: identity.us-phoenix-1.oci.oraclecloud.com"
        );
        assertEquals(expectedSigningString, r.signingString);
        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) host",
                "rsa-sha256",
                TestUtils.SIG_API_NO_DATE
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
    }

    @Test
    void x_date_takes_precedence_over_date_when_both_present() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "de:ad:be:ef";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("identity.us-phoenix-1.oci.oraclecloud.com"));
        headers.put("date", List.of("Mon, 02 Mar 2026 00:00:00 GMT"));
        headers.put("x-date", List.of(TestUtils.FIXED_DATE));

        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        String expectedSigningString = String.join("\n",
                "(request-target): get /20160918/regions",
                "x-date: " + TestUtils.FIXED_DATE,
                "host: identity.us-phoenix-1.oci.oraclecloud.com"
        );
        assertEquals(expectedSigningString, r.signingString);
        assertTrue(r.headersToApply.get("authorization").contains("headers=\"(request-target) x-date host\""));
        TestUtils.verifySignature(r.headersToApply.get("authorization"), r.signingString, kp.getPublic(), "rsa-sha256");
    }

    @Test
    void post_empty_body_still_signs_required_body_headers() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "aa:bb:cc:dd:ee";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("identity.us-phoenix-1.oci.oraclecloud.com"));
        headers.put("date", List.of(TestUtils.FIXED_DATE));
        headers.put("content-type", List.of("application/json"));

        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "POST", "/20160918/compartments",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        String emptyHash = TestUtils.base64Sha256(new byte[0]);
        assertEquals(emptyHash, r.headersToApply.get("x-content-sha256"));
        assertEquals("0", r.headersToApply.get("content-length"));
        assertTrue(r.signingString.contains("x-content-sha256: " + emptyHash));
        assertTrue(r.signingString.contains("content-length: 0"));
        assertTrue(r.headersToApply.get("authorization")
                .contains("headers=\"(request-target) date host x-content-sha256 content-type content-length\""));
        TestUtils.verifySignature(r.headersToApply.get("authorization"), r.signingString, kp.getPublic(), "rsa-sha256");
    }
}
