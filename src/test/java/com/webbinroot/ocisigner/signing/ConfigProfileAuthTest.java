package com.webbinroot.ocisigner.signing;

import com.oracle.bmc.ConfigFileReader;
import com.webbinroot.ocisigner.auth.OciSessionTokenResolver;
import com.webbinroot.ocisigner.model.Profile;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class ConfigProfileAuthTest {

    // Config profile sessionToken: parse from in-memory config and resolve token + key
    @Test
    void config_profile_sessionToken_ok() throws Exception {
        String token = TestUtils.jwtWithExp((System.currentTimeMillis() / 1000) + 3600);
        String profileName = "TEST";
        String keyPemB64 = java.util.Base64.getEncoder()
                .encodeToString(TestUtils.FIXED_PRIVATE_KEY_PEM.getBytes(StandardCharsets.UTF_8));
        String cfgBody = ""
                + "[" + profileName + "]\n"
                + "fingerprint=11:22:33:44:55:66:77\n"
                + "tenancy=ocid1.tenancy.oc1..testtenancy\n"
                + "region=us-phoenix-1\n"
                + "key_file=pem:" + keyPemB64 + "\n"
                + "security_token_file=" + token + "\n";

        ConfigFileReader.ConfigFile cfg = ConfigFileReader.parse(
                new ByteArrayInputStream(cfgBody.getBytes(StandardCharsets.UTF_8)),
                profileName
        );

        Profile p = new Profile("config-profile");
        OciSessionTokenResolver.Material material =
                OciSessionTokenResolver.fromConfigProfile(p, cfg, null, null);
        assertNotNull(material);
        assertEquals(token, material.token);
        assertNotNull(material.privateKey);
    }

    // Config profile without security_token_file returns null material
    @Test
    void config_profile_api_key_returns_null_material() throws Exception {
        String profileName = "APIKEY";
        String keyPemB64 = java.util.Base64.getEncoder()
                .encodeToString(TestUtils.FIXED_PRIVATE_KEY_PEM.getBytes(StandardCharsets.UTF_8));
        String cfgBody = ""
                + "[" + profileName + "]\n"
                + "user=ocid1.user.oc1..testuser\n"
                + "fingerprint=aa:bb:cc:dd:ee\n"
                + "tenancy=ocid1.tenancy.oc1..testtenancy\n"
                + "region=us-phoenix-1\n"
                + "key_file=pem:" + keyPemB64 + "\n";

        ConfigFileReader.ConfigFile cfg = ConfigFileReader.parse(
                new ByteArrayInputStream(cfgBody.getBytes(StandardCharsets.UTF_8)),
                profileName
        );

        Profile p = new Profile("config-profile-api");
        OciSessionTokenResolver.Material material =
                OciSessionTokenResolver.fromConfigProfile(p, cfg, null, null);
        assertNull(material);
    }
}
