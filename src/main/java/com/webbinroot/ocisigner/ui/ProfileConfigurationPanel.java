package com.webbinroot.ocisigner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.webbinroot.ocisigner.auth.OciConfigProfileResolver;
import com.webbinroot.ocisigner.auth.OciCrypto;
import com.webbinroot.ocisigner.signing.OciRequestSigner;
import com.webbinroot.ocisigner.util.OciDebug;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.ProfileStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Top-right profile configuration panel.
 *
 * Profile-level checkboxes are applied live for request handling.
 * Region and static credential fields commit on Save.
 */
public class ProfileConfigurationPanel {

    private final JPanel root;

    private final JLabel header = UiStyles.sectionHeader("Profile Configuration:");
    private final JLabel profileName = new JLabel("");

    private final JLabel statusLabel = new JLabel("Status: —");

    private final JCheckBox inScopeOnly = new JCheckBox("Only sign in-scope requests");
    private final JCheckBox updateTimestamp = new JCheckBox("Update timestamp");
    private final JCheckBox onlyWithAuthHeader =
            new JCheckBox("Only sign if Authorization exists");

    private final JTextField regionField = new JTextField();

    private final JButton testCredentials = new JButton("Test Credentials");
    private final JLabel testCredentialsStatus = new JLabel("");
    private static final String TEST_HEADER = "X-Oci-Signer-Test";
    private static final Color STATUS_OK = new Color(0, 128, 0);
    private static final Color STATUS_FAIL = new Color(176, 0, 0);
    private static final Pattern OCI_REGION_PATTERN =
            Pattern.compile("^[a-z][a-z0-9-]*-[a-z][a-z0-9-]*-[0-9]+$");

    private final StaticCredentialsPanel staticCreds;
    private final MontoyaApi api;

    private Profile currentProfile;
    private boolean suppressDirty = false;

    /**
     * Build the Profile Configuration panel (region, flags, Test Credentials).
     * Example output: panel with profile header + controls.
     */
    public ProfileConfigurationPanel(MontoyaApi api, ProfileStore store) {
        this.api = api;
        root = new JPanel(new GridBagLayout());
        root.setBorder(new EmptyBorder(10, 10, 10, 10));

        staticCreds = new StaticCredentialsPanel(api, store);

        // Save commits this panel + static creds
        staticCreds.setOnSave(() -> {
            applyToCurrentProfile();
            store.saveProfiles(); // prints to Burp output log for now
        });

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        // Header row
        c.gridx = 0; c.gridy = 0; c.gridwidth = 4;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;

        JPanel headerRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        headerRow.setOpaque(false);
        headerRow.add(header);

        // Requested: same size as the orange header
        profileName.setFont(header.getFont());
        headerRow.add(profileName);

        root.add(headerRow, c);

        // Status row
        c.gridy = 1; c.gridx = 0; c.gridwidth = 4;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(statusLabel, c);

        // Options row
        c.gridy = 2; c.gridx = 0; c.gridwidth = 4;
        JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        opts.setOpaque(false);
        opts.add(inScopeOnly);
        opts.add(updateTimestamp);
        onlyWithAuthHeader.setToolTipText("Skip signing unless the request already contains an Authorization header (applies even when scope-only is off).");
        opts.add(onlyWithAuthHeader);
        root.add(opts, c);

        // Region row
        c.gridwidth = 1; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        c.gridy = 3; c.gridx = 0;
        root.add(new JLabel("Region:"), c);

        c.gridx = 1; c.gridwidth = 3;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(regionField, c);

        // Test button
        c.gridy = 4; c.gridx = 1; c.gridwidth = 3;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        JPanel testRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        testRow.setOpaque(false);
        testCredentialsStatus.setForeground(STATUS_FAIL);
        testRow.add(testCredentials);
        testRow.add(testCredentialsStatus);
        root.add(testRow, c);

        // Separator
        c.gridy = 5; c.gridx = 0; c.gridwidth = 4;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(new JSeparator(), c);

        // Static creds panel
        c.gridy = 6; c.gridx = 0; c.gridwidth = 4;
        c.weightx = 1.0; c.weighty = 1.0;
        c.fill = GridBagConstraints.BOTH;
        root.add(staticCreds.getRoot(), c);

        // Apply profile-level behavior:
        // Checkboxes apply immediately without unsaved warning.
        // Region only applies on Save; edits just mark unsaved.
        inScopeOnly.addActionListener(e -> {
            applyToCurrentProfile();
        });
        updateTimestamp.addActionListener(e -> {
            applyToCurrentProfile();
        });
        onlyWithAuthHeader.addActionListener(e -> {
            applyToCurrentProfile();
        });
        regionField.getDocument().addDocumentListener(SimpleDocListener.onChange(() -> {
            markStaticCredsDirty();
        }));

        testCredentials.addActionListener(e -> {
            if (currentProfile == null) {
                logOutput("[OCI Signer][Test] No profile selected.");
                return;
            }

            // Resolve token file paths only when explicitly testing.
            // Region remains save-gated; unsaved region text does not affect tests.
            staticCreds.applyToProfile(currentProfile, true);

            String validationError = validateInputs(currentProfile);
            if (validationError != null) {
                statusLabel.setText("Status: Error");
                testCredentialsStatus.setForeground(STATUS_FAIL);
                testCredentialsStatus.setText(validationError);
                logError("[OCI Signer][Test] " + validationError);
                return;
            }

            testCredentials.setEnabled(false);
            statusLabel.setText("Status: Testing...");
            testCredentialsStatus.setText("");

            SwingWorker<TestOutcome, Void> worker = new SwingWorker<>() {
                @Override
                protected TestOutcome doInBackground() {
                    String result = OciCrypto.testCredentials(currentProfile);
                    Integer namespaceStatus = null;
                    boolean probeAttempted = shouldNamespaceProbe(currentProfile, result);
                    if (probeAttempted) {
                        namespaceStatus = sendNamespaceProbe(currentProfile);
                    }
                    return new TestOutcome(result, namespaceStatus, probeAttempted);
                }

                @Override
                protected void done() {
                    try {
                        TestOutcome outcome = get();
                        String result = (outcome == null) ? null : outcome.result;
                        Integer ns = (outcome == null) ? null : outcome.namespaceStatus;
                        boolean probeAttempted = outcome != null && outcome.namespaceProbeAttempted;

                        boolean ok = result != null && result.startsWith("OK");
                        boolean nsOk = (ns != null && ns == 200);

                        if (probeAttempted && ns == null) {
                            testCredentialsStatus.setForeground(STATUS_FAIL);
                            testCredentialsStatus.setText("Probe failed");
                            statusLabel.setText("Status: Error");
                        } else if (ns != null) {
                            if (nsOk) {
                                testCredentialsStatus.setForeground(STATUS_OK);
                                testCredentialsStatus.setText("HTTP " + ns);
                                statusLabel.setText("Status: OK");
                            } else {
                                testCredentialsStatus.setForeground(STATUS_FAIL);
                                testCredentialsStatus.setText("HTTP " + ns);
                                statusLabel.setText("Status: Error");
                            }
                        } else if (ok) {
                            testCredentialsStatus.setForeground(STATUS_OK);
                            testCredentialsStatus.setText("OK");
                            statusLabel.setText("Status: OK");
                        } else {
                            testCredentialsStatus.setForeground(STATUS_FAIL);
                            testCredentialsStatus.setText("Not Successful");
                            statusLabel.setText("Status: Error");
                        }

                        if (result != null) {
                            logOutput("[OCI Signer][Test] " + result);
                        }
                    } catch (Exception ex) {
                        OciDebug.logStack("[OCI Signer][Test] Test credentials failed", ex);
                        statusLabel.setText("Status: Error");
                        testCredentialsStatus.setForeground(STATUS_FAIL);
                        testCredentialsStatus.setText("Not Successful");
                        logError("[OCI Signer][Test] Test failed: " + ex.getMessage());
                    } finally {
                        testCredentials.setEnabled(true);
                    }
                }
            };

            worker.execute();
        });

        // Critical: initialize from store selection
        setProfile(store.selected());

        // Critical: listen for profile selection changes and update UI
        store.registerListener(msg -> {
            if (msg == null) return;

            // ProfileManagementPanel emits "ui.profileSelected"
            if (msg.contains("ui.profileSelected")
                    || msg.contains("selected_profile")
                    || msg.contains("profile_added")
                    || msg.contains("profile_deleted")
                    || msg.contains("profile_copied")) {

                SwingUtilities.invokeLater(() -> setProfile(store.selected()));
            }
        });
    }

    /**
     * Load profile-level fields into the panel (region, flags).
     * Example input: Profile("Profile1")
     */
    public void setProfile(Profile p) {
        suppressDirty = true;
        try {
            currentProfile = p;

            if (p == null) {
                profileName.setText("");
                statusLabel.setText("Status: —");
                testCredentialsStatus.setText("");
                inScopeOnly.setSelected(false);
                updateTimestamp.setSelected(true);
                onlyWithAuthHeader.setSelected(true);
                regionField.setText("");
                // no extra header overrides
                staticCreds.setProfile(null);
                setEnabledAll(false);
                return;
            }

            profileName.setText(p.name());
            statusLabel.setText("Status: Ready");
            testCredentialsStatus.setText("");

            inScopeOnly.setSelected(p.onlyInScope);
            updateTimestamp.setSelected(p.updateTimestamp);
            onlyWithAuthHeader.setSelected(p.onlyWithAuthHeader);
            regionField.setText(p.region == null ? "" : p.region);

            staticCreds.setProfile(p);
            setEnabledAll(true);
        } finally {
            suppressDirty = false;
        }
    }

    private void applyToCurrentProfile() {
        if (suppressDirty || currentProfile == null) return;

        currentProfile.onlyInScope = inScopeOnly.isSelected();
        currentProfile.updateTimestamp = updateTimestamp.isSelected();
        currentProfile.onlyWithAuthHeader = onlyWithAuthHeader.isSelected();
        currentProfile.region = regionField.getText().trim();
    }

    private void markStaticCredsDirty() {
        if (suppressDirty) return;
        staticCreds.markDirty();
    }

    private void setEnabledAll(boolean enabled) {
        inScopeOnly.setEnabled(enabled);
        updateTimestamp.setEnabled(enabled);
        onlyWithAuthHeader.setEnabled(enabled);
        regionField.setEnabled(enabled);
        testCredentials.setEnabled(enabled);
    }

    /**
     * Return the root Swing component for embedding in the tab.
     */
    public JComponent getRoot() {
        return root;
    }

    private void logOutput(String msg) {
        try {
            if (api != null && msg != null) {
                api.logging().logToOutput(msg);
            }
        } catch (Exception ignored) {}
    }

    private void logError(String msg) {
        try {
            if (api != null && msg != null) {
                api.logging().logToError(msg);
            }
        } catch (Exception ignored) {}
    }

    private boolean shouldNamespaceProbe(Profile p, String testResult) {
        if (p == null) return false;
        AuthType at = (p.authType() == null) ? AuthType.API_KEY : p.authType();
        if (at == AuthType.INSTANCE_PRINCIPAL) return false;
        if (effectiveRegionForTest(p).isBlank()) return false;
        if (testResult == null) return false;
        return testResult.startsWith("OK");
    }

    private String validateInputs(Profile p) {
        if (p == null) return "No profile selected";
        AuthType at = (p.authType() == null) ? AuthType.API_KEY : p.authType();
        java.util.List<String> missing = new java.util.ArrayList<>();

        switch (at) {
            case API_KEY -> {
                if (isBlank(p.tenancyOcid)) missing.add("Tenancy OCID");
                if (isBlank(p.userOcid)) missing.add("User OCID");
                if (isBlank(p.fingerprint)) missing.add("Fingerprint");
                if (isBlank(p.privateKeyPath)) missing.add("Private Key");
            }
            case SECURITY_TOKEN -> {
                if (isBlank(p.sessionToken)) missing.add("Session Token");
                if (isBlank(p.sessionTenancyOcid)) missing.add("Tenancy OCID");
                if (isBlank(p.sessionFingerprint)) missing.add("Fingerprint");
                if (isBlank(p.sessionPrivateKeyPath)) missing.add("Private Key");
            }
            case CONFIG_PROFILE -> {
                if (isBlank(p.configFilePath)) missing.add("Config File");
                if (isBlank(p.configProfileName)) missing.add("Config Profile");
            }
            case INSTANCE_PRINCIPAL -> {
                boolean hasToken = !isBlank(p.cachedSessionToken);
                boolean hasLeaf = !isBlank(p.instanceX509LeafCert);
                boolean hasKey = !isBlank(p.instanceX509LeafKey);
                if (!hasToken && (!hasLeaf || !hasKey)) {
                    missing.add("Leaf Cert");
                    missing.add("Leaf Key");
                }
                if (!hasToken) {
                    boolean hasEndpoint = !isBlank(p.instanceX509FederationEndpoint);
                    boolean hasRegion = !isBlank(p.region);
                    if (!hasEndpoint && !hasRegion) {
                        missing.add("Federation Endpoint or Region");
                    }
                }
            }
            case RESOURCE_PRINCIPAL -> {
                if (isBlank(p.resourcePrincipalRpst)) missing.add("RPST");
                if (isBlank(p.resourcePrincipalPrivateKey)) missing.add("Private Key");
            }
            default -> { }
        }

        // Region is required for test probe targets, except instance principal
        // which may rely on explicit federation endpoint and skips namespace probe.
        if (at != AuthType.INSTANCE_PRINCIPAL) {
            String region = effectiveRegionForTest(p);
            if (region.isBlank()) {
                missing.add("Region");
            } else if (!looksLikeOciRegionId(region)) {
                missing.add("Region (invalid)");
            }
        }

        if (missing.isEmpty()) return null;
        return "Missing: " + String.join(", ", missing);
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private Integer sendNamespaceProbe(Profile p) {
        try {
            String region = effectiveRegionForTest(p);
            if (region.isBlank()) {
                logError("[OCI Signer][Test] Region missing; skipping namespace probe.");
                return null;
            }
            String host = "objectstorage." + region + ".oraclecloud.com";
            String raw =
                    "GET /n/ HTTP/1.1\r\n" +
                    "Host: " + host + "\r\n" +
                    "User-Agent: OCI-Signer-Test\r\n" +
                    TEST_HEADER + ": 1\r\n" +
                    "\r\n";

            HttpService service = HttpService.httpService(host, 443, true);
            HttpRequest req = HttpRequest.httpRequest(service, raw);
            logOutput("[OCI Signer][Test] Namespace probe -> " + host + "/n/ (via Montoya)");
            HttpRequest signed = OciRequestSigner.sign(
                    req,
                    p,
                    api.logging()::logToOutput,
                    api.logging()::logToError,
                    true
            );
            String auth = signed.headerValue("Authorization");
            if (auth == null || auth.isBlank()) {
                logError("[OCI Signer][Test] Namespace probe not signed (Authorization missing).");
            } else {
                logOutput("[OCI Signer][Test] Namespace probe signed (auth len=" + auth.length() + ")");
            }
            HttpRequestResponse resp = api.http().sendRequest(signed);
            if (resp != null && resp.hasResponse()) {
                short status = resp.response().statusCode();
                logOutput("[OCI Signer][Test] Namespace probe status: HTTP " + status);
                return (int) status;
            } else {
                logOutput("[OCI Signer][Test] Namespace probe: no response");
                return null;
            }
        } catch (Exception e) {
            logOutput("[OCI Signer][Test] Namespace probe failed: " + e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : (": " + e.getMessage())));
            logError("[OCI Signer][Test] Namespace probe failed: " + e.getMessage());
            return null;
        }
    }

    private String effectiveRegionForTest(Profile p) {
        if (p == null) return "";
        String uiRegion = p.region == null ? "" : p.region.trim();
        if (!uiRegion.isEmpty()) return normalizeRegionId(uiRegion);

        AuthType at = (p.authType() == null) ? AuthType.API_KEY : p.authType();
        if (at != AuthType.CONFIG_PROFILE) return "";

        if (isBlank(p.configFilePath) || isBlank(p.configProfileName)) return "";
        try {
            OciConfigProfileResolver.ResolvedConfig resolved = OciConfigProfileResolver.resolve(p);
            String cfgRegion = resolved.config == null ? "" : safeTrim(resolved.config.get("region"));
            return normalizeRegionId(cfgRegion);
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String safeTrim(String s) {
        return s == null ? "" : s.trim();
    }

    private static String normalizeRegionId(String region) {
        String v = safeTrim(region);
        if (v.isEmpty()) return "";
        return v.toLowerCase(Locale.ROOT);
    }

    private static boolean looksLikeOciRegionId(String region) {
        if (region == null) return false;
        String v = region.trim().toLowerCase();
        if (v.isEmpty()) return false;
        return OCI_REGION_PATTERN.matcher(v).matches();
    }

    private static final class TestOutcome {
        final String result;
        final Integer namespaceStatus;
        final boolean namespaceProbeAttempted;

        TestOutcome(String result, Integer namespaceStatus, boolean namespaceProbeAttempted) {
            this.result = result;
            this.namespaceStatus = namespaceStatus;
            this.namespaceProbeAttempted = namespaceProbeAttempted;
        }
    }
}
