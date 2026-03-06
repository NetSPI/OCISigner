package com.webbinroot.ocisigner.ui;

import burp.api.montoya.MontoyaApi;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.ProfileStore;
import com.webbinroot.ocisigner.model.SigningMode;
import com.webbinroot.ocisigner.util.OciTokenUtils;
import com.webbinroot.ocisigner.auth.OciX509SessionManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

/**
 * UI panel for all static credential inputs (API key, session token, X509, RPST).
 */
public class StaticCredentialsPanel {

    private final JPanel root;

    private final MontoyaApi api;

    private final JComboBox<AuthType> authType = new JComboBox<>(AuthType.values());

    // Config profile auth (auto)
    private final JTextField configFile = new JTextField();
    private final JTextField configProfile = new JTextField();
    private final JButton browseConfig = new JButton("Browse…");

    private final JLabel authTypeHint = new JLabel("");

    private static final String CARD_API_KEY = "API_KEY";
    private static final String CARD_SESSION = "SESSION";
    private static final String CARD_CONFIG = "CONFIG";
    private static final String CARD_INSTANCE = "INSTANCE";
    private static final String CARD_RESOURCE = "RESOURCE";

    private final JPanel authDetails = new JPanel(new CardLayout());
    private final JPanel apiKeyPanel = new JPanel(new GridBagLayout());
    private final JPanel sessionPanel = new JPanel(new GridBagLayout());
    private final JPanel configProfilePanel = new JPanel(new GridBagLayout());
    // Session Token (direct inputs)
    private final JTextField sessionTenancyOcid = new JTextField();
    private final JTextField sessionFingerprint = new JTextField();
    private final JTextField sessionPrivateKeyFile = new JTextField();
    private final JButton browseSessionKey = new JButton("Browse…");
    private final JPasswordField sessionPrivateKeyPassphrase = new JPasswordField();
    private final TokenField sessionTokenField = new TokenField(4, true, true);
    private final JTextField sessionTokenExpiry = new JTextField();
    private final JTextField sessionTokenCreated = new JTextField();

    // Instance Principal (X509) inputs
    private final JPanel instanceX509Panel = new JPanel(new GridBagLayout());
    private final JTextField instanceLeafCert = new JTextField();
    private final JTextField instanceLeafKey = new JTextField();
    private final JPasswordField instanceLeafKeyPassphrase = new JPasswordField();
    private final JTextField instanceIntermediateCerts = new JTextField();
    private final JTextField instanceFederationEndpoint = new JTextField();
    private final JTextField instanceTenancyOcid = new JTextField();
    private final JButton browseInstanceCert = new JButton("Browse…");
    private final JButton browseInstanceKey = new JButton("Browse…");
    private final JButton addIntermediateCert = new JButton("Add…");
    private final JCheckBox federationProxyEnabled = new JCheckBox("Proxy federation request", true);
    private final JCheckBox federationInsecureTls = new JCheckBox("Disable TLS verify (federation)", false);
    private final JTextField federationProxyHost = new JTextField("127.0.0.1");
    private final JTextField federationProxyPort = new JTextField("8080");
    private final JTextField instanceTokenExpiry = new JTextField();
    private final JTextField instanceTokenCreated = new JTextField();
    private final JButton refreshInstanceToken = new JButton("Refresh Token");
    private final TokenField instanceTokenField = new TokenField(5, false, false);

    // Resource Principal (explicit inputs)
    private final JPanel resourcePrincipalPanel = new JPanel(new GridBagLayout());
    private final TokenField rpstTokenField = new TokenField(4, true, true);
    private final JTextField rpstTokenExpiry = new JTextField();
    private final JTextField rpstTokenCreated = new JTextField();
    private final JTextField rpPrivateKey = new JTextField();
    private final JPasswordField rpPrivateKeyPassphrase = new JPasswordField();
    private final JButton browseRpKey = new JButton("Browse…");
    private final JTextField tenancyOcid = new JTextField();
    private final JTextField userOcid = new JTextField();
    private final JTextField fingerprint = new JTextField();

    private final JTextField privateKeyFile = new JTextField();
    private final JButton browseKey = new JButton("Browse…");

    private final JPasswordField privateKeyPassphrase = new JPasswordField();

    private final JCheckBox modeSdk = new JCheckBox("Standard (OCI SDK)", true);
    private final JCheckBox modeManual = new JCheckBox("Manual (custom)", false);
    private final JButton editManual = new JButton("Edit…");
    private final JPanel signingModePanel = new JPanel(new BorderLayout());

    private final JButton saveButton = new JButton("Save");
    private final JButton openSigCalc = new JButton("Open Signature Calculator…");

    private final JLabel unsavedLabel = new JLabel("Unsaved changes");

    private Runnable onSave = null;

    private boolean suppressEvents = false;
    private boolean dirty = false;

    private Profile currentProfile;
    private AuthType lastAuthType;


    /**
     * Build the Static Credentials UI panel.
     * Example output: a Swing panel with auth-specific inputs and Save button.
     */
    public StaticCredentialsPanel(MontoyaApi api, ProfileStore store) {
        this.api = api;

        root = new JPanel(new GridBagLayout());
        root.setBorder(new EmptyBorder(10, 6, 6, 6));

        Icon warn = UIManager.getIcon("OptionPane.warningIcon");
        if (warn != null) unsavedLabel.setIcon(warn);
        unsavedLabel.setVisible(false);

        editManual.setEnabled(false);

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        int row = 0;

        c.gridx = 0; c.gridy = row++; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        root.add(UiStyles.sectionHeader("Static Credentials Configuration:"), c);

        c.gridwidth = 1; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        c.gridx = 0; c.gridy = row;
        root.add(new JLabel("Auth Type:"), c);

        c.gridx = 1; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(authType, c);
        row++;

        c.gridx = 1; c.gridy = row; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        authTypeHint.setFont(authTypeHint.getFont().deriveFont(Font.ITALIC));
        root.add(authTypeHint, c);
        row++;

        // Auth details are shown via CardLayout to keep the auth type selector visible.
        buildSessionPanel();
        buildConfigProfilePanel();
        buildApiKeyPanel();
        buildInstanceX509Panel();
        buildResourcePrincipalPanel();
        buildSigningModePanel();

        authDetails.add(apiKeyPanel, CARD_API_KEY);
        authDetails.add(sessionPanel, CARD_SESSION);
        authDetails.add(configProfilePanel, CARD_CONFIG);
        authDetails.add(instanceX509Panel, CARD_INSTANCE);
        authDetails.add(resourcePrincipalPanel, CARD_RESOURCE);

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(authDetails, c);
        row++;
        c.gridwidth = 1;

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(signingModePanel, c);
        row++;
        c.gridwidth = 1;

        JPanel saveRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        saveRow.setOpaque(false);
        saveRow.add(saveButton);
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0;
        c.anchor = GridBagConstraints.CENTER;
        c.fill = GridBagConstraints.NONE;
        root.add(saveRow, c);
        row++;
        c.gridwidth = 1;

        c.gridx = 1; c.gridy = row; c.weightx = 1.0;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.NONE;
        root.add(unsavedLabel, c);
        row++;

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        root.add(new JSeparator(SwingConstants.HORIZONTAL), c);
        row++;

        c.gridx = 0; c.gridy = row++; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        root.add(UiStyles.sectionHeader("Signature Calculator:"), c);

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 0;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;
        root.add(openSigCalc, c);
        row++;

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        root.add(new JLabel("Preview a computed Signature for a pasted HTTP request."), c);
        row++;
        c.gridwidth = 1;

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 1.0;
        c.fill = GridBagConstraints.BOTH;
        root.add(Box.createVerticalGlue(), c);

        browseKey.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select OCI API Key Private Key File");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    privateKeyFile.setText(f.getAbsolutePath());
                    markDirty();
                }
            }
        });

        browseSessionKey.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select Session Token Private Key File");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    sessionPrivateKeyFile.setText(f.getAbsolutePath());
                    markDirty();
                }
            }
        });

        if (sessionTokenField.browseButton() != null) {
            sessionTokenField.browseButton().addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select Session Token File");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    sessionTokenField.setTokenValue(f.getAbsolutePath());
                    clearTokenInfo(sessionTokenExpiry, sessionTokenCreated);
                    markDirty();
                }
            }
            });
        }

        browseConfig.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select OCI Config File");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    configFile.setText(f.getAbsolutePath());
                    markDirty();
                }
            }
        });

        browseInstanceCert.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select Instance Principal Leaf Certificate");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    instanceLeafCert.setText(f.getAbsolutePath());
                    markDirty();
                }
            }
        });

        browseInstanceKey.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select Instance Principal Leaf Private Key");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    instanceLeafKey.setText(f.getAbsolutePath());
                    markDirty();
                }
            }
        });

        addIntermediateCert.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select Intermediate Certificate");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    String current = instanceIntermediateCerts.getText().trim();
                    if (!current.isBlank()) {
                        instanceIntermediateCerts.setText(current + ";" + f.getAbsolutePath());
                    } else {
                        instanceIntermediateCerts.setText(f.getAbsolutePath());
                    }
                    markDirty();
                }
            }
        });

        instanceTokenExpiry.setEditable(false);
        instanceTokenCreated.setEditable(false);

        sessionTokenExpiry.setEditable(false);
        sessionTokenCreated.setEditable(false);
        rpstTokenExpiry.setEditable(false);
        rpstTokenCreated.setEditable(false);
        sessionTokenField.setOnTokenEdited(() -> {
            if (suppressEvents) return;
            clearTokenInfo(sessionTokenExpiry, sessionTokenCreated);
            markDirty();
        });
        instanceTokenField.setOnTokenEdited(() -> {
            if (suppressEvents) return;
            clearTokenInfo(instanceTokenExpiry, instanceTokenCreated);
            markDirty();
        });
        rpstTokenField.setOnTokenEdited(() -> {
            if (suppressEvents) return;
            clearTokenInfo(rpstTokenExpiry, rpstTokenCreated);
            markDirty();
        });

        refreshInstanceToken.addActionListener(e -> {
            if (currentProfile == null) return;
            applyToProfile(currentProfile, false);
            OciX509SessionManager.SessionInfo s =
                    OciX509SessionManager.refresh(currentProfile,
                            msg -> logToOutput(msg),
                            msg -> logToOutput(msg));
            updateInstanceTokenUi(currentProfile, s);
            if (s != null && s.token != null) {
                logToOutput("[OCI Signer] X509 token refreshed (len=" + s.token.length() + ")");
            }
        });

        if (rpstTokenField.browseButton() != null) {
            rpstTokenField.browseButton().addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select RPST file");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    rpstTokenField.setTokenValue(f.getAbsolutePath());
                    clearTokenInfo(rpstTokenExpiry, rpstTokenCreated);
                    markDirty();
                }
            }
            });
        }

        browseRpKey.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select Resource Principal Private Key");
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    rpPrivateKey.setText(f.getAbsolutePath());
                    markDirty();
                }
            }
        });

        // Mutual exclusive
        modeSdk.addActionListener(e -> {
            if (suppressEvents) return;
            suppressEvents = true;
            try {
                if (modeSdk.isSelected()) {
                    modeManual.setSelected(false);
                    editManual.setEnabled(false);
                    markDirty();
                } else if (!modeManual.isSelected()) {
                    modeSdk.setSelected(true);
                }
            } finally {
                suppressEvents = false;
            }
        });

        modeManual.addActionListener(e -> {
            if (suppressEvents) return;

            if (modeManual.isSelected()) {
                suppressEvents = true;
                try { modeSdk.setSelected(false); }
                finally { suppressEvents = false; }

                // First time turning manual on: open settings
                if (!openManualSettingsModalAndApply()) {
                    suppressEvents = true;
                    try {
                        modeManual.setSelected(false);
                        modeSdk.setSelected(true);
                        editManual.setEnabled(false);
                    } finally {
                        suppressEvents = false;
                    }
                    return;
                }

                editManual.setEnabled(true);
                markDirty();
            } else {
                suppressEvents = true;
                try {
                    if (!modeSdk.isSelected()) modeSdk.setSelected(true);
                    editManual.setEnabled(false);
                } finally {
                    suppressEvents = false;
                }
                markDirty();
            }
        });

        // NEW: edit button opens modal without needing toggle gymnastics
        editManual.addActionListener(e -> {
            if (currentProfile == null) return;

            // If currently SDK, switching to manual makes sense if you are editing manual settings
            if (!modeManual.isSelected()) {
                suppressEvents = true;
                try {
                    modeManual.setSelected(true);
                    modeSdk.setSelected(false);
                } finally {
                    suppressEvents = false;
                }
            }

            if (openManualSettingsModalAndApply()) {
                editManual.setEnabled(true);
                markDirty();
            }
        });

        tenancyOcid.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        userOcid.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        fingerprint.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        privateKeyFile.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        privateKeyPassphrase.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        configFile.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        configProfile.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        instanceLeafCert.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        instanceLeafKey.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        instanceLeafKeyPassphrase.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        instanceIntermediateCerts.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        instanceFederationEndpoint.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        instanceTenancyOcid.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        federationProxyEnabled.addActionListener(e -> markDirty());
        federationInsecureTls.addActionListener(e -> markDirty());
        federationProxyHost.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        federationProxyPort.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        rpPrivateKey.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));
        rpPrivateKeyPassphrase.getDocument().addDocumentListener(SimpleDocListener.onChange(this::markDirty));

        authType.addActionListener(e -> {
            if (suppressEvents) return;
            applyAuthTypeUi();
            markDirty();
        });

        saveButton.addActionListener(e -> {
            if (currentProfile != null) applyToProfile(currentProfile, true);
            clearDirty();
            if (onSave != null) onSave.run();
        });

        openSigCalc.addActionListener(e -> {
            Window w = SwingUtilities.getWindowAncestor(root);
            SignatureCalculatorDialog dlg = new SignatureCalculatorDialog(w, api, store);
            dlg.setVisible(true);
        });

        // Listen for token refresh events from the signer (no polling).
        OciX509SessionManager.addListener((profile, session) -> {
            if (profile == null || currentProfile == null) return;
            if (!Objects.equals(profile.name(), currentProfile.name())) return;
            SwingUtilities.invokeLater(() -> updateInstanceTokenUi(currentProfile, session));
        });

        setEnabledAll(false);
    }

    /**
     * Register a callback invoked when the user clicks Save.
     * Example input: store::saveProfiles
     */
    public void setOnSave(Runnable r) { this.onSave = r; }

    /**
     * Mark the panel as having unsaved changes (shows warning).
     */
    public void markDirty() {
        if (suppressEvents) return;
        if (!dirty) {
            dirty = true;
            unsavedLabel.setVisible(true);
        }
    }

    private void clearDirty() {
        dirty = false;
        unsavedLabel.setVisible(false);
    }

    /**
     * Load a profile into the UI (no token file I/O).
     * Example input: Profile("Profile1")
     */
    public void setProfile(Profile p) {
        suppressEvents = true;
        try {
            this.currentProfile = p;
            clearDirty();

            if (p == null) {
                setEnabledAll(false);
                authType.setSelectedItem(AuthType.API_KEY);

                configFile.setText("");
                configProfile.setText("");
                authTypeHint.setText("");
                instanceLeafCert.setText("");
                instanceLeafKey.setText("");
                instanceLeafKeyPassphrase.setText("");
                instanceIntermediateCerts.setText("");
                instanceFederationEndpoint.setText("");
                instanceTenancyOcid.setText("");
                federationProxyEnabled.setSelected(true);
                federationInsecureTls.setSelected(false);
                federationProxyHost.setText("127.0.0.1");
                federationProxyPort.setText("8080");
                rpPrivateKey.setText("");
                rpPrivateKeyPassphrase.setText("");

                tenancyOcid.setText("");
                userOcid.setText("");
                fingerprint.setText("");
                privateKeyFile.setText("");
                privateKeyPassphrase.setText("");
                clearTokenInfo(sessionTokenExpiry, sessionTokenCreated);
                clearTokenInfo(instanceTokenExpiry, instanceTokenCreated);
                clearTokenInfo(rpstTokenExpiry, rpstTokenCreated);
                sessionTokenField.clear();
                instanceTokenField.clear();
                rpstTokenField.clear();

                modeSdk.setSelected(true);
                modeManual.setSelected(false);
                editManual.setEnabled(false);

                setPanelEnabled(apiKeyPanel, false);
                setPanelEnabled(sessionPanel, false);
                setPanelEnabled(instanceX509Panel, false);
                setPanelEnabled(resourcePrincipalPanel, false);
                authDetails.setVisible(false);
                return;
            }

            setEnabledAll(true);
            authDetails.setVisible(true);

            authType.setSelectedItem(p.authType() == null ? AuthType.API_KEY : p.authType());
            configFile.setText(p.configFilePath == null ? "" : p.configFilePath);
            configProfile.setText(p.configProfileName == null ? "" : p.configProfileName);
            clearTokenInfo(sessionTokenExpiry, sessionTokenCreated);
            clearTokenInfo(rpstTokenExpiry, rpstTokenCreated);
            sessionTokenField.setTokenValue(p.sessionToken == null ? "" : p.sessionToken);
            sessionTenancyOcid.setText(p.sessionTenancyOcid == null ? "" : p.sessionTenancyOcid);
            sessionFingerprint.setText(p.sessionFingerprint == null ? "" : p.sessionFingerprint);
            sessionPrivateKeyFile.setText(p.sessionPrivateKeyPath == null ? "" : p.sessionPrivateKeyPath);
            sessionPrivateKeyPassphrase.setText(p.sessionPrivateKeyPassphrase == null ? "" : p.sessionPrivateKeyPassphrase);
            // Token display handled by TokenField
            instanceLeafCert.setText(p.instanceX509LeafCert == null ? "" : p.instanceX509LeafCert);
            instanceLeafKey.setText(p.instanceX509LeafKey == null ? "" : p.instanceX509LeafKey);
            instanceLeafKeyPassphrase.setText(p.instanceX509LeafKeyPassphrase == null ? "" : p.instanceX509LeafKeyPassphrase);
            instanceIntermediateCerts.setText(p.instanceX509IntermediateCerts == null ? "" : p.instanceX509IntermediateCerts);
            instanceFederationEndpoint.setText(p.instanceX509FederationEndpoint == null ? "" : p.instanceX509FederationEndpoint);
            instanceTenancyOcid.setText(p.instanceX509TenancyOcid == null ? "" : p.instanceX509TenancyOcid);
            federationProxyEnabled.setSelected(p.federationProxyEnabled);
            federationInsecureTls.setSelected(p.federationInsecureTls);
            federationProxyHost.setText(p.federationProxyHost == null ? "" : p.federationProxyHost);
            federationProxyPort.setText(String.valueOf(p.federationProxyPort));
            rpstTokenField.setTokenValue(p.resourcePrincipalRpst == null ? "" : p.resourcePrincipalRpst);
            rpPrivateKey.setText(p.resourcePrincipalPrivateKey == null ? "" : p.resourcePrincipalPrivateKey);
            rpPrivateKeyPassphrase.setText(p.resourcePrincipalPrivateKeyPassphrase == null ? "" : p.resourcePrincipalPrivateKeyPassphrase);
            // Token display handled by TokenField
            tenancyOcid.setText(p.tenancyOcid == null ? "" : p.tenancyOcid);
            userOcid.setText(p.userOcid == null ? "" : p.userOcid);
            fingerprint.setText(p.fingerprint == null ? "" : p.fingerprint);
            privateKeyFile.setText(p.privateKeyPath == null ? "" : p.privateKeyPath);
            privateKeyPassphrase.setText(p.privateKeyPassphrase == null ? "" : p.privateKeyPassphrase);

            SigningMode sm = (p.signingMode == null) ? SigningMode.SDK : p.signingMode;
            modeSdk.setSelected(sm == SigningMode.SDK);
            modeManual.setSelected(sm == SigningMode.MANUAL);
            editManual.setEnabled(sm == SigningMode.MANUAL);

        } finally {
            if (currentProfile != null) {
                applyAuthTypeUi();
                updateInstanceTokenUi(currentProfile, null);
            }
            suppressEvents = false;
        }
    }

    /**
     * Push current UI values into the Profile.
     *
     * Token file paths are resolved ONLY when resolveTokens=true
     * (i.e., Save/Test Credentials). Typing/browsing does not read files.
     *
     * Example:
     *  - sessionToken="/path/to/token" + resolveTokens=true
     *    -> sessionTokenExpiry/sessionTokenCreated are populated.
     */
    public void applyToProfile(Profile profile) {
        applyToProfile(profile, false);
    }

    /**
     * Push current UI values into the Profile.
     * When resolveTokens=true, token file paths are read and timestamps updated.
     */
    public void applyToProfile(Profile profile, boolean resolveTokens) {
        if (profile == null) return;

        AuthType t = (AuthType) authType.getSelectedItem();
        if (t != null) profile.setAuthType(t);

        profile.configFilePath = configFile.getText().trim();
        profile.configProfileName = configProfile.getText().trim();
        profile.sessionToken = sessionTokenField.tokenValue().trim();
        profile.sessionTenancyOcid = sessionTenancyOcid.getText().trim();
        profile.sessionFingerprint = sessionFingerprint.getText().trim();
        profile.sessionPrivateKeyPath = sessionPrivateKeyFile.getText().trim();
        profile.sessionPrivateKeyPassphrase = new String(sessionPrivateKeyPassphrase.getPassword());
        profile.instanceX509LeafCert = instanceLeafCert.getText().trim();
        profile.instanceX509LeafKey = instanceLeafKey.getText().trim();
        profile.instanceX509LeafKeyPassphrase = new String(instanceLeafKeyPassphrase.getPassword());
        profile.instanceX509IntermediateCerts = instanceIntermediateCerts.getText().trim();
        profile.instanceX509FederationEndpoint = instanceFederationEndpoint.getText().trim();
        profile.instanceX509TenancyOcid = instanceTenancyOcid.getText().trim();
        profile.cachedSessionToken = instanceTokenField.tokenValue().trim();
        if (resolveTokens) {
            updateTokenInfo(profile.sessionToken, sessionTokenExpiry, sessionTokenCreated);
            updateTokenInfo(rpstTokenField.tokenValue(), rpstTokenExpiry, rpstTokenCreated);
            if (profile.cachedSessionToken != null && !profile.cachedSessionToken.isBlank()) {
                String resolved = OciTokenUtils.resolveTokenValue(profile.cachedSessionToken);
                profile.cachedSessionTokenExp = OciTokenUtils.extractJwtExp(resolved);
                profile.cachedSessionTokenUpdatedAt = OciTokenUtils.extractJwtIat(resolved);
                updateTokenInfo(profile.cachedSessionToken, instanceTokenExpiry, instanceTokenCreated);
            } else {
                profile.cachedSessionTokenExp = 0L;
                profile.cachedSessionTokenUpdatedAt = 0L;
                clearTokenInfo(instanceTokenExpiry, instanceTokenCreated);
            }
        }
        profile.federationProxyEnabled = federationProxyEnabled.isSelected();
        profile.federationInsecureTls = federationInsecureTls.isSelected();
        profile.federationProxyHost = federationProxyHost.getText().trim();
        profile.federationProxyPort = parseIntSafe(federationProxyPort.getText().trim(), 8080);
        profile.resourcePrincipalRpst = rpstTokenField.tokenValue().trim();
        profile.resourcePrincipalPrivateKey = rpPrivateKey.getText().trim();
        profile.resourcePrincipalPrivateKeyPassphrase = new String(rpPrivateKeyPassphrase.getPassword());

        profile.tenancyOcid = tenancyOcid.getText().trim();
        profile.userOcid = userOcid.getText().trim();
        profile.fingerprint = fingerprint.getText().trim();
        profile.privateKeyPath = privateKeyFile.getText().trim();
        profile.privateKeyPassphrase = new String(privateKeyPassphrase.getPassword());

        profile.signingMode = modeManual.isSelected() ? SigningMode.MANUAL : SigningMode.SDK;
    }

    private void setEnabledAll(boolean enabled) {
        authType.setEnabled(enabled);
        configFile.setEnabled(enabled);
        configProfile.setEnabled(enabled);
        browseConfig.setEnabled(enabled);
        sessionTokenField.setEnabled(enabled);
        sessionTenancyOcid.setEnabled(enabled);
        sessionFingerprint.setEnabled(enabled);
        sessionPrivateKeyFile.setEnabled(enabled);
        sessionPrivateKeyPassphrase.setEnabled(enabled);
        sessionTokenExpiry.setEnabled(enabled);
        sessionTokenCreated.setEnabled(enabled);
        browseSessionKey.setEnabled(enabled);
        instanceLeafCert.setEnabled(enabled);
        instanceLeafKey.setEnabled(enabled);
        instanceLeafKeyPassphrase.setEnabled(enabled);
        instanceIntermediateCerts.setEnabled(enabled);
        instanceFederationEndpoint.setEnabled(enabled);
        instanceTenancyOcid.setEnabled(enabled);
        browseInstanceCert.setEnabled(enabled);
        browseInstanceKey.setEnabled(enabled);
        addIntermediateCert.setEnabled(enabled);
        instanceTokenField.setEnabled(enabled);
        instanceTokenExpiry.setEnabled(enabled);
        instanceTokenCreated.setEnabled(enabled);
        refreshInstanceToken.setEnabled(enabled);
        rpstTokenField.setEnabled(enabled);
        rpstTokenExpiry.setEnabled(enabled);
        rpstTokenCreated.setEnabled(enabled);
        rpPrivateKey.setEnabled(enabled);
        rpPrivateKeyPassphrase.setEnabled(enabled);
        browseRpKey.setEnabled(enabled);
        tenancyOcid.setEnabled(enabled);
        userOcid.setEnabled(enabled);
        fingerprint.setEnabled(enabled);
        privateKeyFile.setEnabled(enabled);
        privateKeyPassphrase.setEnabled(enabled);
        browseKey.setEnabled(enabled);

        modeSdk.setEnabled(enabled);
        modeManual.setEnabled(enabled);
        editManual.setEnabled(enabled && modeManual.isSelected());

        saveButton.setEnabled(enabled);
        openSigCalc.setEnabled(enabled);
    }

    private static int parseIntSafe(String v, int dflt) {
        try {
            return Integer.parseInt(v);
        } catch (Exception e) {
            return dflt;
        }
    }

    private static JPanel rowWithButton(Component field, Component button) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setOpaque(false);
        row.add(field, BorderLayout.CENTER);
        row.add(button, BorderLayout.EAST);
        return row;
    }

    /**
     * Return the root Swing component for embedding in the tab.
     */
    public JComponent getRoot() { return root; }

    private void buildSessionPanel() {
        sessionPanel.setBorder(BorderFactory.createTitledBorder("Session Token (Direct)"));
        sessionPanel.setOpaque(false);

        FormGrid g = new FormGrid(sessionPanel, new Insets(3, 4, 3, 4));
        g.addLabelField("Tenancy OCID:", sessionTenancyOcid);
        g.addLabelField("Fingerprint:", sessionFingerprint);
        g.addLabelField("Private Key File:", rowWithButton(sessionPrivateKeyFile, browseSessionKey));
        g.addLabelField("Key Passphrase:", sessionPrivateKeyPassphrase);
        g.addLabelField("Session Token (token or file path):",
                sessionTokenField.row(),
                GridBagConstraints.BOTH,
                1.0,
                0.12);
        g.addLabelField("Token Expiry (UTC):", sessionTokenExpiry);
        g.addLabelField("Token Created (UTC):", sessionTokenCreated);
    }

    private void buildConfigProfilePanel() {
        configProfilePanel.setBorder(BorderFactory.createTitledBorder("Config Profile"));
        configProfilePanel.setOpaque(false);

        FormGrid g = new FormGrid(configProfilePanel, new Insets(3, 4, 3, 4));
        g.addLabelField("Config File:", rowWithButton(configFile, browseConfig));
        g.addLabelField("Config Profile:", configProfile);

        JLabel regionNote = new JLabel("* Region set above overrides region in the selected config profile if set.");
        regionNote.setFont(regionNote.getFont().deriveFont(Font.ITALIC));
        g.addFullRow(regionNote);
    }

    private void buildApiKeyPanel() {
        apiKeyPanel.setBorder(BorderFactory.createTitledBorder("API Key"));
        apiKeyPanel.setOpaque(false);

        FormGrid g = new FormGrid(apiKeyPanel, new Insets(3, 4, 3, 4));
        g.addLabelField("Tenancy OCID:", tenancyOcid);
        g.addLabelField("User OCID:", userOcid);
        g.addLabelField("Fingerprint:", fingerprint);
        g.addLabelField("Private Key File:", rowWithButton(privateKeyFile, browseKey));
        g.addLabelField("Key Passphrase:", privateKeyPassphrase);

        // Signing mode is shown globally (not API-key specific).
    }

    private void buildSigningModePanel() {
        signingModePanel.setBorder(BorderFactory.createTitledBorder("Signing Mode"));
        signingModePanel.setOpaque(false);

        JPanel modeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        modeRow.setOpaque(false);
        modeRow.add(modeSdk);
        modeRow.add(modeManual);
        modeRow.add(editManual);

        signingModePanel.add(modeRow, BorderLayout.WEST);
    }

    private void buildInstanceX509Panel() {
        instanceX509Panel.setBorder(BorderFactory.createTitledBorder("Instance Principal (X509 inputs)"));
        instanceX509Panel.setOpaque(false);

        FormGrid g = new FormGrid(instanceX509Panel, new Insets(3, 4, 3, 4));

        g.addLabelField("Leaf Cert:", rowWithButton(instanceLeafCert, browseInstanceCert));
        g.addLabelField("Leaf Key:", rowWithButton(instanceLeafKey, browseInstanceKey));
        g.addLabelField("Key Passphrase:", instanceLeafKeyPassphrase);

        instanceIntermediateCerts.setFont(instanceLeafCert.getFont());
        instanceIntermediateCerts.setBackground(instanceLeafCert.getBackground());
        instanceIntermediateCerts.setToolTipText("Intermediate cert file paths separated by ';' or ','");
        g.addLabelField("Intermediate Certs:", rowWithButton(instanceIntermediateCerts, addIntermediateCert));

        g.addLabelField("Federation Endpoint:", instanceFederationEndpoint);

        JPanel proxyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        proxyRow.setOpaque(false);
        proxyRow.add(new JLabel("Host:"));
        federationProxyHost.setColumns(12);
        proxyRow.add(federationProxyHost);
        proxyRow.add(new JLabel("Port:"));
        federationProxyPort.setColumns(6);
        proxyRow.add(federationProxyPort);

        JPanel proxyLine = new JPanel(new BorderLayout(8, 0));
        proxyLine.setOpaque(false);
        federationProxyEnabled.setToolTipText("Routes federation calls through Burp's proxy listener (ensure the port matches and Burp CA is trusted).");
        proxyLine.add(federationProxyEnabled, BorderLayout.WEST);
        proxyLine.add(proxyRow, BorderLayout.CENTER);

        g.addFullRow(proxyLine);

        JLabel proxyHelp = new JLabel("Used only when fetching the initial session token (Test Credentials / Refresh Token).");
        proxyHelp.setFont(proxyHelp.getFont().deriveFont(Font.ITALIC));
        g.addFullRow(proxyHelp);

        federationInsecureTls.setToolTipText("Disables TLS certificate validation for federation calls (debug only).");
        g.addFullRow(federationInsecureTls);
        g.addLabelField("Tenancy OCID (optional):", instanceTenancyOcid);

        instanceTokenField.setTextBackground(instanceLeafCert.getBackground());
        g.addLabelField("Session Token (cached or token/file path):",
                instanceTokenField.row(),
                GridBagConstraints.BOTH,
                1.0,
                0.12);

        JPanel expiryRow = rowWithButton(instanceTokenExpiry, refreshInstanceToken);
        g.addLabelField("Token Expiry (UTC):", expiryRow);
        g.addLabelField("Token Created (UTC):", instanceTokenCreated);
    }

    private void buildResourcePrincipalPanel() {
        resourcePrincipalPanel.setBorder(BorderFactory.createTitledBorder("Resource Principal (explicit inputs)"));
        resourcePrincipalPanel.setOpaque(false);

        FormGrid g = new FormGrid(resourcePrincipalPanel, new Insets(3, 4, 3, 4));
        g.addLabelField("Private Key (PEM or file path):", rowWithButton(rpPrivateKey, browseRpKey));
        g.addLabelField("Key Passphrase:", rpPrivateKeyPassphrase);
        g.addLabelField("RPST (token or file path):",
                rpstTokenField.row(),
                GridBagConstraints.BOTH,
                1.0,
                0.12);
        g.addLabelField("Token Expiry (UTC):", rpstTokenExpiry);
        g.addLabelField("Token Created (UTC):", rpstTokenCreated);

    }

    private void applyAuthTypeUi() {
        AuthType t = (AuthType) authType.getSelectedItem();
        if (t == null) t = AuthType.API_KEY;

        boolean isApiKey = t == AuthType.API_KEY;
        boolean isConfigProfile = t == AuthType.CONFIG_PROFILE;
        boolean isSession = t == AuthType.SECURITY_TOKEN;
        boolean isInstance = t == AuthType.INSTANCE_PRINCIPAL;
        boolean isResource = t == AuthType.RESOURCE_PRINCIPAL;

        // Keep auth type selector enabled when a profile is active.
        authType.setEnabled(currentProfile != null);

        // Config Profile: require OCI config + profile (auto-detects session token vs API key).
        configFile.setEnabled(isConfigProfile);
        configProfile.setEnabled(isConfigProfile);
        browseConfig.setEnabled(isConfigProfile);
        if (isConfigProfile) {
            if (configFile.getText().trim().isEmpty()) {
                configFile.setText("~/.oci/config");
            }
            if (configProfile.getText().trim().isEmpty()) {
                configProfile.setText("DEFAULT");
            }
        }

        setPanelEnabled(apiKeyPanel, isApiKey);
        setPanelEnabled(sessionPanel, isSession);
        setPanelEnabled(configProfilePanel, isConfigProfile);
        setPanelEnabled(instanceX509Panel, isInstance);
        setPanelEnabled(resourcePrincipalPanel, isResource);

        CardLayout cl = (CardLayout) authDetails.getLayout();
        JComponent shown = null;
        if (isApiKey) { cl.show(authDetails, CARD_API_KEY); shown = apiKeyPanel; }
        else if (isSession) { cl.show(authDetails, CARD_SESSION); shown = sessionPanel; }
        else if (isConfigProfile) { cl.show(authDetails, CARD_CONFIG); shown = configProfilePanel; }
        else if (isInstance) { cl.show(authDetails, CARD_INSTANCE); shown = instanceX509Panel; }
        else if (isResource) { cl.show(authDetails, CARD_RESOURCE); shown = resourcePrincipalPanel; }

        // Reduce excessive empty space when smaller panels are shown (CardLayout uses max preferred size).
        adjustAuthDetailsSize(shown);

        // Force layout refresh when toggling auth-specific panels so the auth-type
        // dropdown doesn't appear to disappear in Burp's UI.
        root.revalidate();
        root.repaint();

        // API key credentials only apply to API Key auth.
        tenancyOcid.setEnabled(isApiKey);
        userOcid.setEnabled(isApiKey);
        fingerprint.setEnabled(isApiKey);
        privateKeyFile.setEnabled(isApiKey);
        privateKeyPassphrase.setEnabled(isApiKey);
        browseKey.setEnabled(isApiKey);

        editManual.setEnabled(modeManual.isSelected());

        // If auth type changed while in manual mode, reset settings to SDK-like defaults.
        if (lastAuthType != t) {
            lastAuthType = t;
            if (!suppressEvents && currentProfile != null) {
                currentProfile.manualSettings = ManualSigningSettings.defaultsLikeSdk();
                markDirty();
            }
        }

        String hint = "";
        if (isSession) {
            hint = "Session token: provide token + key details directly (token may be a file path or raw JWT).";
        } else if (isConfigProfile) {
            hint = "Config profile: auto-detects session token vs API key from the selected config profile.";
        } else if (isInstance) {
            hint = "Instance principal: X.509 leaf cert/key + federation host only (we add /v1/x509). Example: https://auth.us-phoenix-1.oraclecloud.com";
        } else if (isResource) {
            hint = "Resource principal: provide RPST + private key.";
        }
        authTypeHint.setText(hint);

        // Ensure the auth type selector stays visible even if the container scrolls.
        try {
            Rectangle r = authType.getBounds();
            root.scrollRectToVisible(r);
            authType.requestFocusInWindow();
        } catch (Exception ignored) {}
    }

    private static void setPanelEnabled(JComponent c, boolean enabled) {
        if (c == null) return;
        c.setEnabled(enabled);
        for (Component child : c.getComponents()) {
            if (child instanceof JComponent) {
                setPanelEnabled((JComponent) child, enabled);
            } else {
                child.setEnabled(enabled);
            }
        }
    }

    private void adjustAuthDetailsSize(JComponent shown) {
        if (shown == null) return;
        Dimension pref = shown.getPreferredSize();
        if (pref == null) return;

        Dimension cur = authDetails.getPreferredSize();
        int width = (cur != null && cur.width > 0) ? cur.width : pref.width;

        authDetails.setPreferredSize(new Dimension(width, pref.height));
        authDetails.setMinimumSize(new Dimension(0, pref.height));
        authDetails.setMaximumSize(new Dimension(Integer.MAX_VALUE, pref.height));
    }

    private void updateInstanceTokenUi(Profile p, OciX509SessionManager.SessionInfo sessionOverride) {
        if (p == null) {
            instanceTokenField.clear();
            clearTokenInfo(instanceTokenExpiry, instanceTokenCreated);
            return;
        }
        if (sessionOverride != null) {
            String token = (sessionOverride.token == null) ? "" : sessionOverride.token;
            p.cachedSessionToken = token;
            p.cachedSessionTokenExp = sessionOverride.expEpochSec;
            p.cachedSessionTokenUpdatedAt = sessionOverride.refreshedAtEpochSec;
            instanceTokenField.setTokenValue(token);
            updateTokenInfo(token, instanceTokenExpiry, instanceTokenCreated);
            return;
        }

        String token = (p.cachedSessionToken == null) ? "" : p.cachedSessionToken;
        long exp = p.cachedSessionTokenExp;
        long created = p.cachedSessionTokenUpdatedAt;

        if (token.isBlank()) {
            OciX509SessionManager.SessionInfo s = OciX509SessionManager.peek(p);
            token = (s == null || s.token == null) ? "" : s.token;
            exp = (s == null) ? 0L : s.expEpochSec;
            created = (s == null) ? 0L : s.refreshedAtEpochSec;
        }
        if (token.isBlank()) {
            instanceTokenField.clear();
            clearTokenInfo(instanceTokenExpiry, instanceTokenCreated);
            return;
        }
        instanceTokenField.setTokenValue(token);
        if (exp > 0) {
            String expText = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                    .format(Instant.ofEpochSecond(exp).atOffset(ZoneOffset.UTC));
            instanceTokenExpiry.setText(expText);
        } else {
            instanceTokenExpiry.setText("");
        }
        if (created > 0) {
            String createdText = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                    .format(Instant.ofEpochSecond(created).atOffset(ZoneOffset.UTC));
            instanceTokenCreated.setText(createdText);
        } else {
            instanceTokenCreated.setText("");
        }
    }

    private void updateTokenInfo(String tokenInput, JTextField expiryField, JTextField createdField) {
        if (tokenInput == null || tokenInput.trim().isEmpty()) {
            clearTokenInfo(expiryField, createdField);
            return;
        }

        String token = OciTokenUtils.resolveTokenValue(tokenInput);
        long exp = OciTokenUtils.extractJwtExp(token);
        long iat = OciTokenUtils.extractJwtIat(token);

        expiryField.setText(formatEpoch(exp));
        createdField.setText(formatEpoch(iat));
    }

    private String formatEpoch(long epochSec) {
        if (epochSec <= 0) return "";
        return Instant.ofEpochSecond(epochSec).atZone(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    private void clearTokenInfo(JTextField expiryField, JTextField createdField) {
        expiryField.setText("");
        createdField.setText("");
    }

    private void logToOutput(String msg) {
        try {
            if (api != null && msg != null) {
                api.logging().logToOutput(msg);
            }
        } catch (Exception ignored) {}
    }

    private boolean openManualSettingsModalAndApply() {
        if (currentProfile == null) return false;

        ManualSigningSettings existing =
                (currentProfile.manualSettings == null)
                        ? ManualSigningSettings.defaultsLikeSdk()
                        : currentProfile.manualSettings;

        Window w = SwingUtilities.getWindowAncestor(root);
        ManualSigningSettingsDialog dlg = new ManualSigningSettingsDialog(w, existing);
        dlg.setVisible(true);

        ManualSigningSettingsDialog.DialogResult r = dlg.getResult();
        if (r == null || !r.saved || r.settings == null) {
            return false;
        }

        currentProfile.manualSettings = r.settings;

        try {
            if (api != null) {
                api.logging().logToOutput(
                        "[OCI Signer] Saved manual signing settings for profile '" + currentProfile.name() + "': " +
                                r.settings.toLogString()
                );
            }
        } catch (Exception ignored) {}

        return true;
    }
}
