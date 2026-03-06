package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.model.ManualSigningSettings;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OciSigningCoreTest {

    @Test
    void objectStoragePut_only_xContentSha256_present_signs_only_that_optional_header() throws Exception {
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        byte[] body = "hello".getBytes(StandardCharsets.UTF_8);
        String xcs = TestUtils.base64Sha256(body);

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("objectstorage.us-phoenix-1.oraclecloud.com"));
        headers.put("date", List.of(TestUtils.FIXED_DATE));
        headers.put("x-content-sha256", List.of(xcs));

        OciSigningCore.Prepared prepared = OciSigningCore.prepare(
                ms,
                "PUT",
                "/n/ns/b/bkt/o/obj",
                "objectstorage.us-phoenix-1.oraclecloud.com",
                headers,
                body,
                true,
                false,
                OciSigningCore.BodyHeaderPolicy.INCLUDE_PRESENT
        );

        assertEquals(List.of("(request-target)", "date", "host", "x-content-sha256"), prepared.headersToSign);
        assertTrue(prepared.signingString.contains("x-content-sha256: " + xcs));
        assertFalse(prepared.signingString.contains("content-length:"));
        assertFalse(prepared.signingString.contains("content-type:"));
        assertFalse(prepared.headersToApply.containsKey("x-content-sha256"));
        assertFalse(prepared.headersToApply.containsKey("content-length"));
    }

    @Test
    void objectStoragePut_only_contentLength_present_signs_only_that_optional_header() {
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("objectstorage.us-phoenix-1.oraclecloud.com"));
        headers.put("date", List.of(TestUtils.FIXED_DATE));
        headers.put("content-length", List.of("5"));

        OciSigningCore.Prepared prepared = OciSigningCore.prepare(
                ms,
                "PUT",
                "/n/ns/b/bkt/o/obj",
                "objectstorage.us-phoenix-1.oraclecloud.com",
                headers,
                "hello".getBytes(StandardCharsets.UTF_8),
                true,
                false,
                OciSigningCore.BodyHeaderPolicy.INCLUDE_PRESENT
        );

        assertEquals(List.of("(request-target)", "date", "host", "content-length"), prepared.headersToSign);
        assertTrue(prepared.signingString.contains("content-length: 5"));
        assertFalse(prepared.signingString.contains("x-content-sha256:"));
        assertFalse(prepared.signingString.contains("content-type:"));
        assertFalse(prepared.headersToApply.containsKey("x-content-sha256"));
        assertFalse(prepared.headersToApply.containsKey("content-length"));
    }

    @Test
    void objectStoragePut_with_no_optional_body_headers_does_not_add_them() {
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("objectstorage.us-phoenix-1.oraclecloud.com"));
        headers.put("date", List.of(TestUtils.FIXED_DATE));

        OciSigningCore.Prepared prepared = OciSigningCore.prepare(
                ms,
                "PUT",
                "/n/ns/b/bkt/o/obj",
                "objectstorage.us-phoenix-1.oraclecloud.com",
                headers,
                "hello".getBytes(StandardCharsets.UTF_8),
                true,
                false,
                OciSigningCore.BodyHeaderPolicy.INCLUDE_PRESENT
        );

        assertEquals(List.of("(request-target)", "date", "host"), prepared.headersToSign);
        assertFalse(prepared.signingString.contains("x-content-sha256:"));
        assertFalse(prepared.signingString.contains("content-length:"));
        assertTrue(prepared.headersToApply.isEmpty());
    }

    @Test
    void standardPut_empty_body_computes_required_body_headers() throws Exception {
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("identity.us-phoenix-1.oci.oraclecloud.com"));
        headers.put("date", List.of(TestUtils.FIXED_DATE));
        headers.put("content-type", List.of("application/json"));

        OciSigningCore.Prepared prepared = OciSigningCore.prepare(
                ms,
                "PUT",
                "/20160918/compartments/test",
                "identity.us-phoenix-1.oci.oraclecloud.com",
                headers,
                null,
                false,
                false,
                OciSigningCore.BodyHeaderPolicy.INCLUDE_PRESENT
        );

        String emptyHash = TestUtils.base64Sha256(new byte[0]);
        assertEquals(emptyHash, prepared.headersToApply.get("x-content-sha256"));
        assertEquals("0", prepared.headersToApply.get("content-length"));
        assertEquals(
                List.of("(request-target)", "date", "host", "x-content-sha256", "content-type", "content-length"),
                prepared.headersToSign
        );
    }

    @Test
    void xDate_takes_precedence_over_date_in_core_header_selection() {
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of("identity.us-phoenix-1.oci.oraclecloud.com"));
        headers.put("date", List.of("Mon, 02 Mar 2026 00:00:00 GMT"));
        headers.put("x-date", List.of(TestUtils.FIXED_DATE));

        OciSigningCore.Prepared prepared = OciSigningCore.prepare(
                ms,
                "GET",
                "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com",
                headers,
                null,
                false,
                false,
                OciSigningCore.BodyHeaderPolicy.INCLUDE_PRESENT
        );

        assertEquals(List.of("(request-target)", "x-date", "host"), prepared.headersToSign);
        assertTrue(prepared.signingString.contains("x-date: " + TestUtils.FIXED_DATE));
        assertFalse(prepared.signingString.contains("date: Mon, 02 Mar 2026 00:00:00 GMT"));
    }
}
