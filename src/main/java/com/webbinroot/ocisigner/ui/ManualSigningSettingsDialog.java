package com.webbinroot.ocisigner.ui;

import com.webbinroot.ocisigner.model.ManualSigningSettings;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;

public class ManualSigningSettingsDialog extends JDialog {

    public static final class DialogResult {
        public final boolean saved;
        public final ManualSigningSettings settings;

        /**
         * Dialog result wrapper.
         * Example output: saved=true, settings=<ManualSigningSettings>
         */
        public DialogResult(boolean saved, ManualSigningSettings settings) {
            this.saved = saved;
            this.settings = settings;
        }
    }

    private DialogResult result;

    // Supported by current Manual signer implementation (RSA + HMAC).
    private static final String[] ALGORITHMS = new String[] {
            "rsa-sha256",
            "rsa-sha384",
            "rsa-sha512",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512"
    };

    private final JComboBox<String> algorithm = new JComboBox<>(ALGORITHMS);

    private final JCheckBox signRequestTarget = new JCheckBox("(request-target)  (pseudo-header)", true);
    private final JCheckBox signDate = new JCheckBox("date", true);
    private final JCheckBox signHost = new JCheckBox("host", true);

    private final JCheckBox signXContentSha256 = new JCheckBox("x-content-sha256", true);
    private final JCheckBox signContentType = new JCheckBox("content-type", true);
    private final JCheckBox signContentLength = new JCheckBox("content-length", true);

    private final JCheckBox allowGetWithBody = new JCheckBox("Allow GET with body", false);
    private final JCheckBox allowDeleteWithBody = new JCheckBox("Allow DELETE with body", false);

    private final JCheckBox addMissingDate = new JCheckBox("If missing, auto-add date", true);
    private final JCheckBox addMissingHost = new JCheckBox("If missing, auto-add/derive host (when possible)", true);
    private final JCheckBox computeMissingXContentSha256 = new JCheckBox("If missing, compute x-content-sha256", true);
    private final JCheckBox computeMissingContentLength = new JCheckBox("If missing, compute content-length", true);

    private final JTextArea extraHeaders = new JTextArea(6, 60);
    private final JTextField signedHeadersPreview = new JTextField();

    // -----------------------------
    // HMAC UI
    // -----------------------------
    private final JPanel hmacPanel = new JPanel(new GridBagLayout());
    private final JRadioButton hmacTextMode = new JRadioButton("Text / base64:", true);
    private final JRadioButton hmacFileMode = new JRadioButton("File", false);

    private final JPasswordField hmacKeyText = new JPasswordField();
    private final JTextField hmacKeyFile = new JTextField();
    private final JButton hmacBrowse = new JButton("Browse…");

    /**
     * Build the manual signing settings dialog.
     * Example input: initial=defaultsLikeSdk()
     */
    public ManualSigningSettingsDialog(Window parent, ManualSigningSettings initial) {
        super(parent, "Manual Signing Settings", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        ManualSigningSettings working =
                (initial == null) ? ManualSigningSettings.defaultsLikeSdk() : initial.copy();

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(new EmptyBorder(12, 12, 12, 12));
        setContentPane(content);

        JPanel header = new JPanel(new BorderLayout(6, 6));
        header.add(UiStyles.sectionHeader("Manual (custom) signing settings"), BorderLayout.NORTH);
        header.add(new JLabel("<html>" +
                "These options control how <b>custom signing</b> builds the Authorization Signature.<br/>" +
                "(request-target) is a <i>pseudo-header</i> (not a real HTTP header)." +
                "</html>"), BorderLayout.CENTER);
        content.add(header, BorderLayout.NORTH);

        JPanel main = new JPanel(new GridBagLayout());
        content.add(main, BorderLayout.CENTER);

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);
        c.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Algorithm
        c.gridx = 0; c.gridy = row; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        main.add(new JLabel("Algorithm:"), c);

        c.gridx = 1; c.gridy = row; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        main.add(algorithm, c);
        row++;

        // HMAC panel (conditionally visible)
        buildHmacPanel();
        c.gridx = 0; c.gridy = row; c.gridwidth = 2; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        main.add(hmacPanel, c);
        row++;
        c.gridwidth = 1;

        // Headers to include
        c.gridx = 0; c.gridy = row++; c.gridwidth = 2; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        main.add(UiStyles.sectionHeader("Headers to include in signature"), c);

        JPanel headerChecks = new JPanel(new GridLayout(0, 2, 10, 4));
        headerChecks.setOpaque(false);

        headerChecks.add(signRequestTarget);
        headerChecks.add(signDate);
        headerChecks.add(signHost);

        headerChecks.add(signXContentSha256);
        headerChecks.add(signContentType);
        headerChecks.add(signContentLength);

        c.gridx = 0; c.gridy = row; c.gridwidth = 2; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        main.add(headerChecks, c);
        row++;

        // Extra headers
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        main.add(new JLabel("Extra signed headers (one per line):"), c);
        row++;

        extraHeaders.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane extraScroll = new JScrollPane(extraHeaders);
        extraScroll.setPreferredSize(new Dimension(600, 120));

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 0;
        c.fill = GridBagConstraints.BOTH;
        main.add(extraScroll, c);
        row++;

        // Deviations section
        c.gridx = 0; c.gridy = row++; c.gridwidth = 2; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        main.add(UiStyles.sectionHeader("Deviations from standard"), c);

        JPanel dev = new JPanel(new GridLayout(0, 1, 8, 2));
        dev.setOpaque(false);
        dev.add(allowGetWithBody);
        dev.add(allowDeleteWithBody);
        dev.add(addMissingDate);
        dev.add(addMissingHost);
        dev.add(computeMissingXContentSha256);
        dev.add(computeMissingContentLength);

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        main.add(dev, c);
        row++;

        // Preview
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        main.add(new JLabel("Signed headers preview (order):"), c);
        row++;

        signedHeadersPreview.setEditable(false);
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        main.add(signedHeadersPreview, c);
        row++;

        // Buttons
        JButton setDefault = new JButton("Set Default");
        JButton save = new JButton("Save");
        JButton cancel = new JButton("Cancel");

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(setDefault);
        buttons.add(save);
        buttons.add(cancel);
        content.add(buttons, BorderLayout.SOUTH);

        loadSettingsIntoUI(working);

        Runnable updateUi = () -> {
            ManualSigningSettings tmp = captureSettingsFromUI();
            signedHeadersPreview.setText(String.join(" ", tmp.defaultHeaderOrderPreview()));

            // show/hide hmac panel based on algorithm
            boolean showHmac = tmp.isHmacAlgorithm();
            hmacPanel.setVisible(showHmac);

            // enable proper controls
            boolean textMode = hmacTextMode.isSelected();
            hmacKeyText.setEnabled(showHmac && textMode);
            hmacKeyFile.setEnabled(showHmac && !textMode);
            hmacBrowse.setEnabled(showHmac && !textMode);
        };

        algorithm.addActionListener(e -> updateUi.run());

        signRequestTarget.addActionListener(e -> updateUi.run());
        signDate.addActionListener(e -> updateUi.run());
        signHost.addActionListener(e -> updateUi.run());
        signXContentSha256.addActionListener(e -> updateUi.run());
        signContentType.addActionListener(e -> updateUi.run());
        signContentLength.addActionListener(e -> updateUi.run());

        allowGetWithBody.addActionListener(e -> updateUi.run());
        allowDeleteWithBody.addActionListener(e -> updateUi.run());
        addMissingDate.addActionListener(e -> updateUi.run());
        addMissingHost.addActionListener(e -> updateUi.run());
        computeMissingXContentSha256.addActionListener(e -> updateUi.run());
        computeMissingContentLength.addActionListener(e -> updateUi.run());

        extraHeaders.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { updateUi.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { updateUi.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { updateUi.run(); }
        });

        hmacTextMode.addActionListener(e -> updateUi.run());
        hmacFileMode.addActionListener(e -> updateUi.run());

        hmacBrowse.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select HMAC Key File");
            int r = fc.showOpenDialog(hmacPanel);
            if (r == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                if (f != null) {
                    hmacKeyFile.setText(f.getAbsolutePath());
                    updateUi.run();
                }
            }
        });

        updateUi.run();

        setDefault.addActionListener(e -> {
            loadSettingsIntoUI(ManualSigningSettings.defaultsLikeSdk());
            updateUi.run();
        });

        save.addActionListener(e -> {
            ManualSigningSettings out = captureSettingsFromUI();

            // basic validation for HMAC modes
            if (out.isHmacAlgorithm()) {
                if (out.hmacKeyMode == ManualSigningSettings.HmacKeyMode.TEXT) {
                    String t = new String(hmacKeyText.getPassword()).trim();
                    if (t.isEmpty()) {
                        JOptionPane.showMessageDialog(this,
                                "HMAC algorithm selected but HMAC key is empty.\n" +
                                        "Enter key text, or use base64:... format, or choose File mode.",
                                "Missing HMAC Key",
                                JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                } else {
                    if (out.hmacKeyFilePath == null || out.hmacKeyFilePath.trim().isEmpty()) {
                        JOptionPane.showMessageDialog(this,
                                "HMAC algorithm selected but no HMAC key file was chosen.",
                                "Missing HMAC Key File",
                                JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                }
            }

            result = new DialogResult(true, out);
            dispose();
        });

        cancel.addActionListener(e -> {
            result = new DialogResult(false, null);
            dispose();
        });

        pack();
        setMinimumSize(new Dimension(800, 700));
        setLocationRelativeTo(parent);
    }

    /**
     * Return dialog result after close.
     * Example output: DialogResult(saved=true, settings=...)
     */
    public DialogResult getResult() {
        return result;
    }

    private void buildHmacPanel() {
        hmacPanel.setOpaque(false);
        hmacPanel.setBorder(BorderFactory.createTitledBorder("HMAC Key (for hmac-* algorithms)"));

        ButtonGroup g = new ButtonGroup();
        g.add(hmacTextMode);
        g.add(hmacFileMode);

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        int row = 0;

        c.gridx = 0; c.gridy = row; c.weightx = 0;
        hmacPanel.add(hmacTextMode, c);

        c.gridx = 1; c.gridy = row; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        hmacKeyText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        hmacPanel.add(hmacKeyText, c);
        row++;

        c.gridx = 0; c.gridy = row; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        hmacPanel.add(hmacFileMode, c);

        JPanel fileRow = new JPanel(new BorderLayout(6, 0));
        fileRow.setOpaque(false);
        fileRow.add(hmacKeyFile, BorderLayout.CENTER);
        fileRow.add(hmacBrowse, BorderLayout.EAST);

        c.gridx = 1; c.gridy = row; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        hmacPanel.add(fileRow, c);

        JLabel hint = new JLabel("<html><i>Text mode supports:</i> raw text (UTF-8) or <code>base64:....</code></html>");
        c.gridx = 0; c.gridy = ++row; c.gridwidth = 2; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        hmacPanel.add(hint, c);
    }

    private void loadSettingsIntoUI(ManualSigningSettings s) {
        if (s == null) s = ManualSigningSettings.defaultsLikeSdk();

        algorithm.setSelectedItem(nz(s.algorithm, "rsa-sha256"));

        signRequestTarget.setSelected(s.signRequestTarget);
        signDate.setSelected(s.signDate);
        signHost.setSelected(s.signHost);

        signXContentSha256.setSelected(s.signXContentSha256);
        signContentType.setSelected(s.signContentType);
        signContentLength.setSelected(s.signContentLength);

        allowGetWithBody.setSelected(s.allowGetWithBody);
        allowDeleteWithBody.setSelected(s.allowDeleteWithBody);

        addMissingDate.setSelected(s.addMissingDate);
        addMissingHost.setSelected(s.addMissingHost);
        computeMissingXContentSha256.setSelected(s.computeMissingXContentSha256);
        computeMissingContentLength.setSelected(s.computeMissingContentLength);

        extraHeaders.setText(s.extraSignedHeaders == null ? "" : s.extraSignedHeaders);

        // HMAC
        if (s.hmacKeyMode == ManualSigningSettings.HmacKeyMode.FILE) {
            hmacFileMode.setSelected(true);
        } else {
            hmacTextMode.setSelected(true);
        }
        hmacKeyFile.setText(s.hmacKeyFilePath == null ? "" : s.hmacKeyFilePath);
        hmacKeyText.setText(s.hmacKeyText == null ? "" : s.hmacKeyText);
    }

    private ManualSigningSettings captureSettingsFromUI() {
        ManualSigningSettings s = new ManualSigningSettings();

        Object alg = algorithm.getSelectedItem();
        s.algorithm = (alg == null) ? "rsa-sha256" : alg.toString();

        s.signRequestTarget = signRequestTarget.isSelected();
        s.signDate = signDate.isSelected();
        s.signHost = signHost.isSelected();

        s.signXContentSha256 = signXContentSha256.isSelected();
        s.signContentType = signContentType.isSelected();
        s.signContentLength = signContentLength.isSelected();

        s.allowGetWithBody = allowGetWithBody.isSelected();
        s.allowDeleteWithBody = allowDeleteWithBody.isSelected();

        s.addMissingDate = addMissingDate.isSelected();
        s.addMissingHost = addMissingHost.isSelected();
        s.computeMissingXContentSha256 = computeMissingXContentSha256.isSelected();
        s.computeMissingContentLength = computeMissingContentLength.isSelected();

        s.extraSignedHeaders = extraHeaders.getText() == null ? "" : extraHeaders.getText();

        // HMAC
        s.hmacKeyMode = hmacFileMode.isSelected()
                ? ManualSigningSettings.HmacKeyMode.FILE
                : ManualSigningSettings.HmacKeyMode.TEXT;

        s.hmacKeyText = new String(hmacKeyText.getPassword());
        s.hmacKeyFilePath = hmacKeyFile.getText() == null ? "" : hmacKeyFile.getText().trim();

        return s;
    }

    private static String nz(String v, String dflt) {
        if (v == null) return dflt;
        String t = v.trim();
        return t.isEmpty() ? dflt : t;
    }
}
