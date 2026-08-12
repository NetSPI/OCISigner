package com.webbinroot.ocisigner.signing;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.SigningMode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers OciRequestSigner.sign(HttpRequest, ...) itself -- the actual entry point the
 * live HttpHandler and the Test Credentials probe both call. Every other signing test
 * in this suite exercises OciManualSigner/OciSessionTokenSigner/OciSigningCore
 * directly on a plain header map, which never touches this class's Montoya-HttpRequest
 * wiring (buildUriForSigning, toHeaderMultimap, applyHeaders) or its request-level
 * gating (INTERNAL_TEST_HEADER force-sign, onlyWithAuthHeader, federation-endpoint skip).
 */
class OciRequestSignerTest {

    @Test
    void internalTestHeader_forceSigns_and_is_stripped_even_when_onlyWithAuthHeader_blocks() {
        Profile p = TestUtils.apiKeyProfile("api-key");
        p.signingMode = SigningMode.MANUAL;
        p.onlyWithAuthHeader = true;
        p.updateTimestamp = false;

        String host = "identity.us-phoenix-1.oci.oraclecloud.com";
        HttpRequest req = MontoyaFakes.fakeHttpRequest(
                "GET /20160918/regions HTTP/1.1\r\n" +
                        "Host: " + host + "\r\n" +
                        "Date: " + TestUtils.FIXED_DATE + "\r\n" +
                        OciRequestSigner.INTERNAL_TEST_HEADER + ": 1\r\n" +
                        "\r\n");

        HttpRequest signed = OciRequestSigner.sign(req, p, null, null, false);

        String auth = signed.headerValue("Authorization");
        assertNotNull(auth);
        assertTrue(auth.startsWith("Signature "));
        assertFalse(signed.hasHeader(OciRequestSigner.INTERNAL_TEST_HEADER));
    }

    @Test
    void onlyWithAuthHeader_skips_signing_when_no_authorization_present() {
        Profile p = TestUtils.apiKeyProfile("api-key");
        p.signingMode = SigningMode.MANUAL;
        p.onlyWithAuthHeader = true;

        String host = "identity.us-phoenix-1.oci.oraclecloud.com";
        HttpRequest req = MontoyaFakes.fakeHttpRequest(
                "GET /20160918/regions HTTP/1.1\r\nHost: " + host + "\r\n\r\n");

        HttpRequest result = OciRequestSigner.sign(req, p, null, null, false);

        assertNull(result.headerValue("Authorization"));
    }

    @Test
    void onlyWithAuthHeader_signs_when_authorization_already_present() {
        Profile p = TestUtils.apiKeyProfile("api-key");
        p.signingMode = SigningMode.MANUAL;
        p.onlyWithAuthHeader = true;
        p.updateTimestamp = false;

        String host = "identity.us-phoenix-1.oci.oraclecloud.com";
        HttpRequest req = MontoyaFakes.fakeHttpRequest(
                "GET /20160918/regions HTTP/1.1\r\n" +
                        "Host: " + host + "\r\n" +
                        "Date: " + TestUtils.FIXED_DATE + "\r\n" +
                        "Authorization: Bearer placeholder\r\n" +
                        "\r\n");

        HttpRequest result = OciRequestSigner.sign(req, p, null, null, false);

        String auth = result.headerValue("Authorization");
        assertNotNull(auth);
        assertTrue(auth.startsWith("Signature "));
    }

    @Test
    void federation_endpoint_requests_are_never_signed_to_avoid_recursion() {
        // Path-based rule: /v1/x509 is always skipped regardless of host, since a
        // user-supplied custom federation endpoint won't necessarily match "auth.*".
        Profile p = TestUtils.apiKeyProfile("api-key");
        p.setAuthType(AuthType.INSTANCE_PRINCIPAL);
        p.onlyWithAuthHeader = false;

        String host = "identity.us-phoenix-1.oci.oraclecloud.com";
        HttpRequest req = MontoyaFakes.fakeHttpRequest(
                "GET /v1/x509 HTTP/1.1\r\nHost: " + host + "\r\n\r\n");

        HttpRequest result = OciRequestSigner.sign(req, p, null, null, false);

        assertNull(result.headerValue("Authorization"));
    }

    @Test
    void manual_apiKey_end_to_end_via_montoya_request_matches_lower_level_signer() {
        // Cross-checks against ApiKeySigningTest's identical scenario: same profile,
        // same request, same fixed signature -- proves the Montoya HttpRequest ->
        // header-multimap -> OciManualSigner -> applyHeaders round trip is lossless.
        Profile p = TestUtils.apiKeyProfile("api-key");
        p.signingMode = SigningMode.MANUAL;
        p.onlyWithAuthHeader = false;
        p.updateTimestamp = false;

        String host = "objectstorage.us-phoenix-1.oraclecloud.com";
        HttpRequest req = MontoyaFakes.fakeHttpRequest(
                "GET /n/namespace HTTP/1.1\r\n" +
                        "Host: " + host + "\r\n" +
                        "Date: " + TestUtils.FIXED_DATE + "\r\n" +
                        "\r\n");

        HttpRequest signed = OciRequestSigner.sign(req, p, null, null, false);

        String auth = signed.headerValue("Authorization");
        assertNotNull(auth);
        String keyId = p.tenancyOcid + "/" + p.userOcid + "/" + p.fingerprint;
        assertEquals(keyId, TestUtils.extractParam(auth, "keyId"));
        assertEquals("rsa-sha256", TestUtils.extractParam(auth, "algorithm"));
        assertEquals(TestUtils.SIG_API_GET, TestUtils.extractParam(auth, "signature"));
    }
}
