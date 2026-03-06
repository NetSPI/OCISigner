package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class InstancePrincipalSigningTest {

    // Instance principal sessionToken signing valid
    @Test
    void instance_principal_sessionToken_signing_valid() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("instance-principal");
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

        String auth = r.headersToApply.get("authorization");
        assertNotNull(auth);
        String expectedAuth = TestUtils.expectedSessionAuthorizationHeaderWithSig(
                "ST$" + token,
                "(request-target) date host",
                "rsa-sha256",
                TestUtils.SIG_SESSION_IDENTITY
        );
        assertEquals(expectedAuth, auth);
        TestUtils.verifySignature(auth, r.signingString, kp.getPublic(), "rsa-sha256");
    }
}
