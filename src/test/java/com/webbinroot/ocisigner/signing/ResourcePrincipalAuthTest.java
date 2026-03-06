package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.auth.OciRpstSessionManager;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ResourcePrincipalAuthTest {

    // ResourcePrincipal sessionManager loads token and key
    @Test
    void resourcePrincipal_sessionManager_loads_token_and_key() throws Exception {
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        long exp = (System.currentTimeMillis() / 1000) + 3600;
        String token = TestUtils.jwtWithExp(exp);

        Profile p = new Profile("rpst-manager");
        p.setAuthType(AuthType.RESOURCE_PRINCIPAL);
        p.resourcePrincipalRpst = token;
        p.resourcePrincipalPrivateKey = keyPath;

        var info = OciRpstSessionManager.refresh(p, null, null);
        assertNotNull(info);
        assertEquals(token, info.token);
        assertNotNull(info.sessionPrivateKey);
        assertEquals(exp, info.expEpochSec);
    }

    // ResourcePrincipal missing key returns null
    @Test
    void resourcePrincipal_missing_key_returns_null() {
        Profile p = new Profile("rpst-missing");
        p.setAuthType(AuthType.RESOURCE_PRINCIPAL);
        p.resourcePrincipalRpst = TestUtils.jwtWithExp((System.currentTimeMillis() / 1000) + 3600);
        p.resourcePrincipalPrivateKey = "";

        var info = OciRpstSessionManager.refresh(p, null, null);
        assertNull(info);
    }

    // ResourcePrincipal sessionToken signing valid
    @Test
    void resourcePrincipal_sessionToken_signing_valid() throws Exception {
        KeyPair kp = TestUtils.fixedKeyPair();
        Profile p = new Profile("rpst");
        p.setAuthType(AuthType.RESOURCE_PRINCIPAL);
        ManualSigningSettings ms = ManualSigningSettings.defaultsLikeSdk();

        Map<String, List<String>> headers =
                TestUtils.baseHeaders("objectstorage.us-phoenix-1.oraclecloud.com");
        String token = "rpst.jwt.token";

        OciSessionTokenSigner.Result r = OciSessionTokenSigner.sign(
                p, token, kp.getPrivate(), ms, "GET", "/n/namespace",
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
        String expectedAuth = TestUtils.expectedSessionAuthorizationHeaderWithSig(
                "ST$" + token,
                "(request-target) date host",
                "rsa-sha256",
                TestUtils.SIG_SESSION_OBJECTSTORAGE
        );
        assertEquals(expectedAuth, auth);
        TestUtils.verifySignature(auth, r.signingString, kp.getPublic(), "rsa-sha256");
    }
}
