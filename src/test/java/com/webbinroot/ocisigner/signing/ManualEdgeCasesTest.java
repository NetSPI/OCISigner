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

class ManualEdgeCasesTest {

    // Get with body allowed includes body headers and full header
    @Test
    void get_with_body_allowed_includes_body_headers_and_full_header() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "11:22:33:44:55:66:77";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        ms.allowGetWithBody = true;

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("identity.us-phoenix-1.oci.oraclecloud.com"));
        headers.put("date", List.of(TestUtils.FIXED_DATE));
        headers.put("content-type", List.of("application/json"));

        byte[] body = "{\"x\":1}".getBytes(StandardCharsets.UTF_8);
        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, body
        );

        String xcs = TestUtils.base64Sha256(body);
        String cl = String.valueOf(body.length);
        String expectedSigningString = String.join("\n",
                "(request-target): get /20160918/regions",
                "date: " + TestUtils.FIXED_DATE,
                "host: identity.us-phoenix-1.oci.oraclecloud.com",
                "x-content-sha256: " + xcs,
                "content-type: application/json",
                "content-length: " + cl
        );
        assertEquals(expectedSigningString, r.signingString);

        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host x-content-sha256 content-type content-length",
                "rsa-sha256",
                TestUtils.SIG_API_GET_WITH_BODY
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
        TestUtils.verifySignature(r.headersToApply.get("authorization"), r.signingString, kp.getPublic(), "rsa-sha256");
    }

    // Delete with body allowed includes body headers and full header
    @Test
    void delete_with_body_allowed_includes_body_headers_and_full_header() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "11:22:33:44:55:66:77";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        ms.allowDeleteWithBody = true;

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("objectstorage.us-phoenix-1.oraclecloud.com"));
        headers.put("date", List.of(TestUtils.FIXED_DATE));
        headers.put("content-type", List.of("application/json"));

        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "DELETE", "/n/namespace",
                "objectstorage.us-phoenix-1.oraclecloud.com", headers, body
        );

        String xcs = TestUtils.base64Sha256(body);
        String cl = String.valueOf(body.length);
        String expectedSigningString = String.join("\n",
                "(request-target): delete /n/namespace",
                "date: " + TestUtils.FIXED_DATE,
                "host: objectstorage.us-phoenix-1.oraclecloud.com",
                "x-content-sha256: " + xcs,
                "content-type: application/json",
                "content-length: " + cl
        );
        assertEquals(expectedSigningString, r.signingString);

        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host x-content-sha256 content-type content-length",
                "rsa-sha256",
                TestUtils.SIG_API_DELETE_WITH_BODY
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
        TestUtils.verifySignature(r.headersToApply.get("authorization"), r.signingString, kp.getPublic(), "rsa-sha256");
    }

    // SignDate disabled full header matches
    @Test
    void signDate_disabled_full_header_matches() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "11:22:33:44:55:66:77";
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
        TestUtils.verifySignature(r.headersToApply.get("authorization"), r.signingString, kp.getPublic(), "rsa-sha256");
    }

    // ObjectStoragePut ignores body headers when missing
    @Test
    void objectStoragePut_ignores_body_headers_when_missing() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "11:22:33:44:55:66:77";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = TestUtils.baseHeaders("objectstorage.us-phoenix-1.oraclecloud.com");
        byte[] body = "hello".getBytes(StandardCharsets.UTF_8);

        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "PUT", "/n/namespace/b/bucket/o/object",
                "objectstorage.us-phoenix-1.oraclecloud.com", headers, body
        );

        String expectedSigningString = String.join("\n",
                "(request-target): put /n/namespace/b/bucket/o/object",
                "date: " + TestUtils.FIXED_DATE,
                "host: objectstorage.us-phoenix-1.oraclecloud.com"
        );
        assertEquals(expectedSigningString, r.signingString);

        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host",
                "rsa-sha256",
                TestUtils.SIG_API_OBJECTSTORAGE_PUT
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
        TestUtils.verifySignature(r.headersToApply.get("authorization"), r.signingString, kp.getPublic(), "rsa-sha256");
    }

    // Extra headers duplicate defaults are deduped (header list stays stable)
    @Test
    void extra_headers_duplicates_are_deduped() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "11:22:33:44:55:66:77";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        ms.extraSignedHeaders = "host\nHOST\nhost";

        Map<String, List<String>> headers = TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        String expectedSigningString = String.join("\n",
                "(request-target): get /20160918/regions",
                "date: " + TestUtils.FIXED_DATE,
                "host: identity.us-phoenix-1.oci.oraclecloud.com"
        );
        assertEquals(expectedSigningString, r.signingString);

        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host",
                "rsa-sha256",
                TestUtils.SIG_SESSION_IDENTITY
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
        TestUtils.verifySignature(r.headersToApply.get("authorization"), r.signingString, kp.getPublic(), "rsa-sha256");
    }

    // ObjectStoragePut signs body headers when present (manual mode)
    @Test
    void objectStoragePut_includes_present_body_headers() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "11:22:33:44:55:66:77";
        p.privateKeyPath = keyPath;

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = TestUtils.baseHeaders("objectstorage.us-phoenix-1.oraclecloud.com");
        byte[] body = "hello".getBytes(StandardCharsets.UTF_8);
        String xcs = TestUtils.base64Sha256(body);
        headers.put("content-type", List.of("application/octet-stream"));
        headers.put("content-length", List.of(String.valueOf(body.length)));
        headers.put("x-content-sha256", List.of(xcs));

        OciManualSigner.Result r = OciManualSigner.sign(
                p, ms, "PUT", "/n/namespace/b/bucket/o/object",
                "objectstorage.us-phoenix-1.oraclecloud.com", headers, body
        );

        String expectedSigningString = String.join("\n",
                "(request-target): put /n/namespace/b/bucket/o/object",
                "date: " + TestUtils.FIXED_DATE,
                "host: objectstorage.us-phoenix-1.oraclecloud.com",
                "x-content-sha256: " + xcs,
                "content-type: application/octet-stream",
                "content-length: " + body.length
        );
        assertEquals(expectedSigningString, r.signingString);

        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host x-content-sha256 content-type content-length",
                "rsa-sha256",
                TestUtils.SIG_API_OBJECTSTORAGE_PUT_WITH_BODY_HEADERS
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
        TestUtils.verifySignature(r.headersToApply.get("authorization"), r.signingString, kp.getPublic(), "rsa-sha256");
    }

    // Hmac sha256 signing fixed signature
    @Test
    void hmac_sha256_signing_fixed_signature() throws Exception {
        Profile p = new Profile("api-key");
        p.tenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.userOcid = "ocid1.user.oc1..testuser";
        p.fingerprint = "11:22:33:44:55:66:77";

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        ms.algorithm = "hmac-sha256";
        ms.hmacKeyText = "base64:aGVsbG8="; // \"hello\"

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

        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        String expectedAuth = TestUtils.expectedManualAuthorizationHeaderWithSig(
                keyId,
                "(request-target) date host",
                "hmac-sha256",
                TestUtils.SIG_HMAC_GET
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
    }
}
