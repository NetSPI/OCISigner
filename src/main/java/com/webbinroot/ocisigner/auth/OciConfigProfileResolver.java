package com.webbinroot.ocisigner.auth;

import com.oracle.bmc.ConfigFileReader;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.util.OciTokenUtils;

import java.io.IOException;

/**
 * Shared resolver for OCI config profiles.
 *
 * Centralizes:
 *  - default profile name handling
 *  - config file path expansion
 *  - detection of security_token_file
 *  - API key profile extraction
 */
public final class OciConfigProfileResolver {

    public static final class ResolvedConfig {
        public final String configPath;
        public final String profileName;
        public final ConfigFileReader.ConfigFile config;
        public final boolean hasSecurityToken;

        private ResolvedConfig(String configPath,
                               String profileName,
                               ConfigFileReader.ConfigFile config,
                               boolean hasSecurityToken) {
            this.configPath = configPath;
            this.profileName = profileName;
            this.config = config;
            this.hasSecurityToken = hasSecurityToken;
        }
    }

    private OciConfigProfileResolver() {}

    /**
     * Resolve config file + profile name.
     *
     * Example input:
     *  - configFilePath="~/.oci/config", configProfileName="DEFAULT"
     * Example output:
     *  - ResolvedConfig(configPath="/home/kali/.oci/config", profileName="DEFAULT", ...)
     */
    public static ResolvedConfig resolve(Profile p) throws IOException {
        String path = OciTokenUtils.expandHome(nz(p == null ? "" : p.configFilePath));
        String prof = nz(p == null ? "" : p.configProfileName);
        if (prof.isBlank()) prof = "DEFAULT";
        ConfigFileReader.ConfigFile cfg = ConfigFileReader.parse(path, prof);
        return new ResolvedConfig(path, prof, cfg, hasSecurityToken(cfg));
    }

    /**
     * Check if config contains security_token_file.
     * Example output: true if security_token_file is present.
     */
    public static boolean hasSecurityToken(ConfigFileReader.ConfigFile cfg) {
        String tokenFile = (cfg == null) ? null : cfg.get("security_token_file");
        return tokenFile != null && !tokenFile.trim().isBlank();
    }

    /**
     * Build a Profile with API key fields from a config profile.
     * Example output: tenancy/user/fingerprint/privateKeyPath filled from cfg.
     */
    public static Profile apiKeyProfileFromConfig(ConfigFileReader.ConfigFile cfg) {
        Profile tmp = new Profile("config-profile");
        tmp.tenancyOcid = (cfg == null) ? "" : nz(cfg.get("tenancy"));
        tmp.userOcid = (cfg == null) ? "" : nz(cfg.get("user"));
        tmp.fingerprint = (cfg == null) ? "" : nz(cfg.get("fingerprint"));
        tmp.privateKeyPath = OciTokenUtils.expandHome(nz((cfg == null) ? "" : cfg.get("key_file")));
        tmp.privateKeyPassphrase = (cfg == null) ? "" : nz(cfg.get("pass_phrase"));
        return tmp;
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }
}
