package com.webbinroot.ocisigner.auth;

import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.Profile;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Repro for the "Config Profile (Auto) keeps using the old credentials after
 * `oci session authenticate` rotates them" bug: SIGNER_CACHE's key (configFilePath +
 * configProfileName + region) never changes across a rotation, so without content-based
 * invalidation the cached signer is held forever. This directly verifies the
 * invalidation hash itself changes when the underlying config/token content changes.
 */
class ConfigProfileRefreshReproTest {

    @Test
    void contentHashChangesWhenFingerprintAndTokenRotate() throws Exception {
        Path dir = Files.createTempDirectory("ocisigner-config-repro");
        Path tokenFile = dir.resolve("token");
        Files.writeString(tokenFile, "original-token-content");

        Path configPath = dir.resolve("config");
        writeConfig(configPath, "SESSION_CRED_TEST", "aa:bb:cc:first", tokenFile);

        Profile p = new Profile("test");
        p.setAuthType(AuthType.CONFIG_PROFILE);
        p.configFilePath = configPath.toString();
        p.configProfileName = "SESSION_CRED_TEST";
        p.region = "us-phoenix-1";

        Method m = OciCrypto.class.getDeclaredMethod("configProfileContentHash", Profile.class);
        m.setAccessible(true);

        String hashBefore = (String) m.invoke(null, p);

        // Simulate `oci session authenticate`: new key pair (new fingerprint) + rotated
        // token content, config file path/profile name/region all unchanged (that's
        // exactly what made SIGNER_CACHE's old key-only check miss this).
        Thread.sleep(20);
        writeConfig(configPath, "SESSION_CRED_TEST", "dd:ee:ff:second", tokenFile);
        Files.writeString(tokenFile, "rotated-token-content");
        OciConfigProfileResolver.clear(); // bust its own mtime-keyed cache for this repro

        String hashAfter = (String) m.invoke(null, p);

        System.out.println("hashBefore=" + hashBefore);
        System.out.println("hashAfter=" + hashAfter);

        assertNotEquals(hashBefore, hashAfter, "content hash must change after fingerprint+token rotation");
    }

    private static void writeConfig(Path configPath, String section, String fingerprint, Path tokenFile) throws Exception {
        String content = "[" + section + "]\n"
                + "tenancy=ocid1.tenancy.oc1..fake\n"
                + "fingerprint=" + fingerprint + "\n"
                + "key_file=" + tokenFile + "\n" // doesn't need to be a real key for this test
                + "security_token_file=" + tokenFile + "\n"
                + "region=us-phoenix-1\n";
        Files.writeString(configPath, content);
    }
}
