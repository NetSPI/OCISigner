package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.auth.OciCrypto;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.Profile;
import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.*;

class SecurityTokenAuthTest {

    // SecurityToken direct provider ok
    @Test
    void securityToken_direct_provider_ok() throws Exception {
        String keyPath = TestUtils.FIXED_PRIVATE_KEY_PEM;

        long exp = (System.currentTimeMillis() / 1000) + 3600;
        String token = TestUtils.jwtWithExp(exp);

        Profile p = new Profile("security-token");
        p.setAuthType(AuthType.SECURITY_TOKEN);
        p.sessionTenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.sessionFingerprint = "aa:bb:cc:dd:ee";
        p.sessionPrivateKeyPath = keyPath;
        p.sessionToken = token;

        String result = OciCrypto.testCredentials(p);
        assertNotNull(result);
        assertTrue(result.startsWith("OK"));
    }

    // SecurityToken missing fields throws
    @Test
    void securityToken_missing_fields_throws() {
        Profile p = new Profile("security-token-missing");
        p.setAuthType(AuthType.SECURITY_TOKEN);
        p.sessionTenancyOcid = "ocid1.tenancy.oc1..testtenancy";
        p.sessionFingerprint = "";
        p.sessionPrivateKeyPath = "";
        p.sessionToken = "";
        String result = OciCrypto.testCredentials(p);
        assertNotNull(result);
        assertTrue(result.startsWith("FAILED"));
    }
}
