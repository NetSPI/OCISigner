package com.webbinroot.ocisigner.model;

import java.util.Objects;

/**
 * Profile holds per-credential + per-signing behavior settings.
 *
 * NOTE:
 *  - Mutable POJO (UI edits it).
 *  - Persisting is currently event-driven via ProfileStore.saveProfiles()
 *    (your UI prints to output log when "saved").
 */
public class Profile {

    private final String name;

    // volatile: every field below is written from the EDT on Save (or, for the cached
    // token fields, from the signing/federation-refresh path -- including the
    // background refresh thread introduced for the token-refresh fix) and read from
    // Burp's HTTP-handling thread on every live signing pass. Plain fields have no
    // cross-thread visibility guarantee without this -- same reasoning as
    // ProfileStore's fields. This closes the "reader never sees the update" case;
    // it does not make a read of multiple fields atomic as a group (see project notes).

    // ----- Per-profile behavior -----
    public volatile boolean onlyInScope = false;

    // If enabled, we set Date to "now" before signing (SDK path behavior)
    public volatile boolean updateTimestamp = true;

    // Optional helper inputs (used only for in-scope checks)
    public volatile String region = "";

    // If enabled, only sign requests that already include an Authorization header
    public volatile boolean onlyWithAuthHeader = true;

    // ----- Auth / signing -----
    private volatile AuthType authType = AuthType.API_KEY;
    public volatile SigningMode signingMode = SigningMode.SDK;

    // Session token auth (security token) uses OCI config file + profile.
    // Example CLI workflow writes security_token_file into config profile.
    public volatile String configFilePath = "~/.oci/config";
    public volatile String configProfileName = "DEFAULT";

    // Session token (direct) inputs
    public volatile String sessionToken = ""; // token string or file path
    public volatile String sessionTenancyOcid = "";
    public volatile String sessionFingerprint = "";
    public volatile String sessionPrivateKeyPath = "";
    public volatile String sessionPrivateKeyPassphrase = "";

    // Instance principal X.509 inputs (optional, for non-IMDS environments)
    public volatile String instanceX509LeafCert = "";
    public volatile String instanceX509LeafKey = "";
    public volatile String instanceX509LeafKeyPassphrase = "";
    public volatile String instanceX509IntermediateCerts = "";
    public volatile String instanceX509FederationEndpoint = "";
    public volatile String instanceX509TenancyOcid = "";
    public volatile String federationProxyHost = "127.0.0.1";
    public volatile int federationProxyPort = 8080;
    public volatile boolean federationProxyEnabled = true;
    public volatile boolean federationInsecureTls = false;

    // Cached instance principal session token (in-memory only; not persisted/exported)
    public volatile String cachedSessionToken = "";
    public volatile long cachedSessionTokenExp = 0L;
    public volatile long cachedSessionTokenUpdatedAt = 0L;

    // Resource principal inputs (optional, for non-env environments)
    public volatile String resourcePrincipalRpst = "";
    public volatile String resourcePrincipalPrivateKey = "";
    public volatile String resourcePrincipalPrivateKeyPassphrase = "";

    // Delegation token (OBO) -- optional add-on for Instance Principal only (Oracle's
    // SDKs only ship a dedicated delegation signer for instance principals). Attached
    // as "opc-obo-token" on every request and included in the signed headers set; the
    // underlying instance-principal signer still produces the signature. Value or file
    // path (resolved via OciTokenUtils.resolveTokenValue, re-read on every sign -- so a
    // rotating token like Cloud Shell's /etc/oci/delegation_token is picked up
    // automatically).
    public volatile String delegationToken = "";

    // Static credentials
    public volatile String tenancyOcid;
    public volatile String userOcid;
    public volatile String fingerprint;
    public volatile String privateKeyPath;
    public volatile String privateKeyPassphrase; // currently not used by SDK signer

    // Manual (custom) mode settings
    public volatile ManualSigningSettings manualSettings = new ManualSigningSettings();

    public Profile(String name) {
        // Example input: "Prod"
        this.name = Objects.requireNonNull(name, "name");
    }

    /**
     * Deep-ish copy for "Copy Profile": every configured input, none of the
     * in-memory-only cached session state (that's tied to this profile's own
     * cache key elsewhere, not something a copy should inherit).
     */
    public Profile copy(String newName) {
        Profile c = new Profile(newName);

        c.onlyInScope = this.onlyInScope;
        c.updateTimestamp = this.updateTimestamp;
        c.region = this.region;
        c.onlyWithAuthHeader = this.onlyWithAuthHeader;
        c.authType = this.authType;
        c.signingMode = this.signingMode;

        c.configFilePath = this.configFilePath;
        c.configProfileName = this.configProfileName;

        c.sessionToken = this.sessionToken;
        c.sessionTenancyOcid = this.sessionTenancyOcid;
        c.sessionFingerprint = this.sessionFingerprint;
        c.sessionPrivateKeyPath = this.sessionPrivateKeyPath;
        c.sessionPrivateKeyPassphrase = this.sessionPrivateKeyPassphrase;

        c.instanceX509LeafCert = this.instanceX509LeafCert;
        c.instanceX509LeafKey = this.instanceX509LeafKey;
        c.instanceX509LeafKeyPassphrase = this.instanceX509LeafKeyPassphrase;
        c.instanceX509IntermediateCerts = this.instanceX509IntermediateCerts;
        c.instanceX509FederationEndpoint = this.instanceX509FederationEndpoint;
        c.instanceX509TenancyOcid = this.instanceX509TenancyOcid;
        c.federationProxyHost = this.federationProxyHost;
        c.federationProxyPort = this.federationProxyPort;
        c.federationProxyEnabled = this.federationProxyEnabled;
        c.federationInsecureTls = this.federationInsecureTls;

        c.resourcePrincipalRpst = this.resourcePrincipalRpst;
        c.resourcePrincipalPrivateKey = this.resourcePrincipalPrivateKey;
        c.resourcePrincipalPrivateKeyPassphrase = this.resourcePrincipalPrivateKeyPassphrase;

        c.delegationToken = this.delegationToken;

        c.tenancyOcid = this.tenancyOcid;
        c.userOcid = this.userOcid;
        c.fingerprint = this.fingerprint;
        c.privateKeyPath = this.privateKeyPath;
        c.privateKeyPassphrase = this.privateKeyPassphrase;

        c.manualSettings = (this.manualSettings == null) ? null : this.manualSettings.copy();

        return c;
    }

    public String name() { return name; }

    public boolean inScopeOnly() { return onlyInScope; }

    public void setInScopeOnly(boolean v) { this.onlyInScope = v; }

    public AuthType authType() { return authType; }

    /**
     * Set the auth type (null defaults to API_KEY).
     * Example input: AuthType.INSTANCE_PRINCIPAL
     */
    public void setAuthType(AuthType t) {
        this.authType = (t == null) ? AuthType.API_KEY : t;
    }

    @Override
    public String toString() { return name; }
}
