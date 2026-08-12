package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Delegation (OBO) token support: an optional add-on to Instance Principal signing
 * only (Oracle's SDKs only ship a dedicated delegation signer for instance
 * principals). Verifies opc-obo-token is stamped on the request AND included in the
 * signed-headers set, that it's inert for every other auth type, and that it's
 * resolved fresh (raw value or file path) on every sign.
 */
class DelegationTokenSigningTest {

    @Test
    void instancePrincipal_delegationToken_included_in_signedHeaders_and_signingString() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("instance-principal-delegation");
        p.setAuthType(AuthType.INSTANCE_PRINCIPAL);
        p.delegationToken = "obo.jwt.token";

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers = TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        String token = "ip.jwt.token";
        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                p, token, kp.getPrivate(), ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        String expectedSigningString = String.join("\n",
                "(request-target): get /20160918/regions",
                "date: " + TestUtils.FIXED_DATE,
                "host: identity.us-phoenix-1.oci.oraclecloud.com",
                "opc-obo-token: obo.jwt.token"
        );
        assertEquals(expectedSigningString, r.signingString);

        assertEquals("obo.jwt.token", r.headersToApply.get("opc-obo-token"));

        String auth = r.headersToApply.get("authorization");
        assertNotNull(auth);
        assertEquals("(request-target) date host opc-obo-token", TestUtils.extractParam(auth, "headers"));
        TestUtils.verifySignature(auth, r.signingString, kp.getPublic(), "rsa-sha256");
    }

    @Test
    void delegationToken_ignored_for_default_authType() throws Exception {
        // Mirrors SessionTokenSigningTest's bare `new Profile(...)`, which defaults to
        // API_KEY -- proves a stray delegationToken value never leaks into unrelated
        // auth types, even though this function is the shared choke point for all of
        // them (live signing, Test Credentials, Signature Calculator).
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("default-auth");
        p.delegationToken = "should.not.appear";

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers = TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                p, "dummy.session.token", kp.getPrivate(), ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        assertFalse(r.headersToApply.containsKey("opc-obo-token"));
        assertFalse(r.signingString.contains("opc-obo-token"));
    }

    @Test
    void delegationToken_ignored_for_resourcePrincipal_authType() throws Exception {
        // Explicit regression guard for the scoping decision: Resource Principal does
        // NOT get delegation support (no dedicated Oracle SDK signer for it), even
        // though it shares this exact code path with Instance Principal for everything
        // else.
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("resource-principal");
        p.setAuthType(AuthType.RESOURCE_PRINCIPAL);
        p.delegationToken = "should.not.appear";

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers = TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                p, "dummy.rpst.token", kp.getPrivate(), ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        assertFalse(r.headersToApply.containsKey("opc-obo-token"));
        assertFalse(r.signingString.contains("opc-obo-token"));
    }

    @Test
    void delegationToken_blank_is_byte_identical_to_no_delegation() throws Exception {
        // Regression safety: default (blank) delegationToken must reproduce exactly
        // the same output as InstancePrincipalSigningTest's existing assertions.
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("instance-principal-no-delegation");
        p.setAuthType(AuthType.INSTANCE_PRINCIPAL);

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers = TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        String token = "ip.jwt.token";
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
        assertFalse(r.headersToApply.containsKey("opc-obo-token"));

        String expectedAuth = TestUtils.expectedSessionAuthorizationHeaderWithSig(
                "ST$" + token,
                "(request-target) date host",
                "rsa-sha256",
                TestUtils.SIG_SESSION_IDENTITY
        );
        assertEquals(expectedAuth, r.headersToApply.get("authorization"));
    }

    @Test
    void delegationToken_resolved_from_file_path(@TempDir Path tempDir) throws Exception {
        Path tokenFile = tempDir.resolve("delegation_token");
        Files.writeString(tokenFile, "obo.from.file\n");

        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("instance-principal-file-delegation");
        p.setAuthType(AuthType.INSTANCE_PRINCIPAL);
        p.delegationToken = tokenFile.toAbsolutePath().toString();

        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();
        Map<String, List<String>> headers = TestUtils.baseHeaders("identity.us-phoenix-1.oci.oraclecloud.com");

        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                p, "ip.jwt.token", kp.getPrivate(), ms, "GET", "/20160918/regions",
                "identity.us-phoenix-1.oci.oraclecloud.com", headers, null
        );

        assertEquals("obo.from.file", r.headersToApply.get("opc-obo-token"));
        assertTrue(r.signingString.contains("opc-obo-token: obo.from.file"));
    }
}
