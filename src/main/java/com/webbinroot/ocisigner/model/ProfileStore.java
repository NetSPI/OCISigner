package com.webbinroot.ocisigner.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ProfileStore {

    public interface StoreListener {
        /**
         * Called when the store changes.
         * Example input: "profile_added"
         */
        void onChange(String event);
    }

    private final List<StoreListener> listeners = new ArrayList<>();

    private void fire(String event) {
        for (StoreListener l : listeners) {
            try { l.onChange(event); } catch (Exception ignored) {}
        }
    }

    /**
     * Register a listener for store events.
     * Example input: event -> "profile_saved"
     */
    public void registerListener(StoreListener l) {
        if (l != null) listeners.add(l);
    }

    // -----------------------------
    // Profiles (in-memory)
    // -----------------------------
    private final List<Profile> profiles = new ArrayList<>();
    private Profile selected = null;

    // -----------------------------
    // Global settings (in-memory)
    // -----------------------------
    private boolean signingEnabled = false;

    // nullable => No Profile
    private Profile alwaysSignWith = null;

    private String logLevel = "Error";

    /**
     * Initialize store with a default profile.
     * Example output: Profile1 selected + set as default signer.
     */
    public ProfileStore() {
        Profile p1 = new Profile("Profile1");
        profiles.add(p1);

        selected = p1;
        alwaysSignWith = p1;
    }

    /**
     * Return all profiles (in-memory list).
     * Example output: [Profile1, Profile2]
     */
    public List<Profile> all() { return profiles; }

    /**
     * Return the selected profile (may be null).
     */
    public Profile selected() { return selected; }

    /**
     * Select a profile and notify listeners.
     * Example input: Profile "Profile2"
     */
    public void select(Profile p) {
        selected = p;
        fire("selected_profile");
    }

    /**
     * Add a new profile with auto-incremented name.
     * Example output: Profile3
     */
    public Profile addNew() {
        int n = profiles.size() + 1;
        Profile p = new Profile("Profile" + n);
        profiles.add(p);
        selected = p;
        fire("profile_added");
        return p;
    }

    /**
     * Add a fully-constructed profile (used by Import dialog).
     * Caller should ensure the name is unique.
     */
    public void addImported(Profile p) {
        if (p == null) return;
        profiles.add(p);
        selected = p;

        // If no global profile set yet, prefer first imported.
        if (alwaysSignWith == null) {
            alwaysSignWith = p;
        }

        fire("profile_imported");
        fire("selected_profile");
    }

    /**
     * Convenience: create and add an imported profile with a given name.
     * Returns the created Profile.
     */
    /**
     * Convenience: create and add a profile with a specific name.
     * Example input: "Prod"
     * Example output: Profile("Prod")
     */
    public Profile addImportedProfile(String name) {
        Profile p = new Profile(name);
        addImported(p);
        return p;
    }

    /**
     * For now: "persistence" means emit an event (UI can log it).
     * Future: write to disk / Burp persistence API.
     */
    /**
     * Persist profiles (currently event-only).
     * Example output event: "profiles_saved"
     */
    public void saveProfiles() {
        fire("profiles_saved");
    }

    /**
     * Delete a profile and adjust selection/defaults.
     * Example input: Profile("Profile2")
     */
    public void delete(Profile p) {
        profiles.remove(p);

        if (profiles.isEmpty()) {
            selected = null;
            alwaysSignWith = null;
        } else {
            if (selected == p) selected = profiles.get(0);
            if (alwaysSignWith == p) alwaysSignWith = null; // prefer No Profile rather than silently changing
        }

        fire("profile_deleted");
    }

    /**
     * Deep-copy a profile into a new profile with suffix "_copy".
     * Example input: Profile("Profile1") -> "Profile1_copy"
     */
    public Profile copy(Profile p) {
        Profile c = new Profile(p.name() + "_copy");

        c.setInScopeOnly(p.inScopeOnly());
        c.setAuthType(p.authType());
        c.updateTimestamp = p.updateTimestamp;
        c.signingMode = p.signingMode;
        c.onlyWithAuthHeader = p.onlyWithAuthHeader;
        c.configFilePath = p.configFilePath;
        c.configProfileName = p.configProfileName;
        c.instanceX509LeafCert = p.instanceX509LeafCert;
        c.instanceX509LeafKey = p.instanceX509LeafKey;
        c.instanceX509LeafKeyPassphrase = p.instanceX509LeafKeyPassphrase;
        c.instanceX509IntermediateCerts = p.instanceX509IntermediateCerts;
        c.instanceX509FederationEndpoint = p.instanceX509FederationEndpoint;
        c.instanceX509TenancyOcid = p.instanceX509TenancyOcid;
        c.federationProxyHost = p.federationProxyHost;
        c.federationProxyPort = p.federationProxyPort;
        c.federationProxyEnabled = p.federationProxyEnabled;
        c.federationInsecureTls = p.federationInsecureTls;
        c.resourcePrincipalRpst = p.resourcePrincipalRpst;
        c.resourcePrincipalPrivateKey = p.resourcePrincipalPrivateKey;
        c.resourcePrincipalPrivateKeyPassphrase = p.resourcePrincipalPrivateKeyPassphrase;

        c.tenancyOcid = p.tenancyOcid;
        c.userOcid = p.userOcid;
        c.fingerprint = p.fingerprint;
        c.privateKeyPath = p.privateKeyPath;
        c.privateKeyPassphrase = p.privateKeyPassphrase;

        c.region = p.region;

        // Manual settings are mutable; keep a copy so edits don't affect the original profile.
        c.manualSettings = (p.manualSettings == null) ? null : p.manualSettings.copy();

        profiles.add(c);
        selected = c;

        fire("profile_copied");
        return c;
    }

    /**
     * Lookup a profile by name.
     * Example input: "Profile1" -> Optional.of(Profile1)
     */
    public Optional<Profile> byName(String name) {
        return profiles.stream().filter(p -> p.name().equals(name)).findFirst();
    }

    // -----------------------------
    // Global config accessors
    // -----------------------------
    /**
     * Return whether signing is globally enabled.
     */
    public boolean signingEnabled() { return signingEnabled; }

    /**
     * Enable/disable signing globally.
     * Example input: true
     */
    public void setSigningEnabled(boolean enabled) {
        signingEnabled = enabled;
        fire("global_signing_enabled");
    }

    /**
     * Return the "always sign with" profile (may be null).
     */
    public Profile alwaysSignWith() { return alwaysSignWith; }

    /**
     * Set signing profile. null => No Profile (sign nothing).
     */
    public void setAlwaysSignWith(Profile p) {
        alwaysSignWith = p;
        if (p != null) selected = p;
        fire("global_always_sign_with");
        fire("selected_profile");
    }

    /**
     * Return current log level string ("Error"/"Info"/"Debug").
     */
    public String logLevel() { return logLevel; }

    /**
     * Set log level for diagnostics.
     * Example input: "Debug"
     */
    public void setLogLevel(String lvl) {
        logLevel = (lvl == null || lvl.isBlank()) ? "Error" : lvl;
        fire("global_log_level");
    }

    // -----------------------------
    // Change notifications
    // -----------------------------
    /**
     * Fire a custom change event.
     * Example input: "profile_saved"
     */
    public void changed(String event) { fire(event); }

    /**
     * Fire a custom change event (profile unused but keeps API flexible).
     */
    public void changed(String event, Profile profile) { fire(event); }
}
