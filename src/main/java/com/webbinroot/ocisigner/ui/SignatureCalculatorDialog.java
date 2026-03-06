package com.webbinroot.ocisigner.ui;

import burp.api.montoya.MontoyaApi;
import com.webbinroot.ocisigner.signing.OciSignatureCalculator;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.ProfileStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Signature Calculator modal:
 *  - Paste raw HTTP request
 *  - Click Calculate
 *  - Get computed Authorization Signature + debug canonicalization output
 */
public class SignatureCalculatorDialog extends JDialog {

    private final MontoyaApi api;
    private final ProfileStore store;

    private final JTextArea requestInput = new JTextArea(16, 80);

    private final JTextField signatureOut = new JTextField();
    private final JButton calcButton = new JButton("Calculate");
    private final JButton clearButton = new JButton("Clear");
    private final JButton closeButton = new JButton("Close");

    private final JTextArea debugOut = new JTextArea(14, 80);

    /**
     * Build the signature calculator dialog.
     * Example input: raw HTTP request -> Authorization signature output.
     */
    public SignatureCalculatorDialog(Window parent, MontoyaApi api, ProfileStore store) {
        super(parent, "Signature Calculator", ModalityType.APPLICATION_MODAL);
        this.api = api;
        this.store = store;

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(new EmptyBorder(12, 12, 12, 12));
        setContentPane(content);

        JPanel header = new JPanel(new BorderLayout(8, 8));
        header.add(UiStyles.sectionHeader("Signature Calculator"), BorderLayout.NORTH);

        JTextArea help = new JTextArea(
                "Paste a raw HTTP request (start-line + headers + optional body).\n" +
                "Click Calculate to generate the OCI Authorization: Signature ... value " +
                "using the currently selected profile."
        );
        help.setEditable(false);
        help.setLineWrap(true);
        help.setWrapStyleWord(true);
        help.setOpaque(false);
        help.setFocusable(false);
        header.add(help, BorderLayout.CENTER);

        content.add(header, BorderLayout.NORTH);

        requestInput.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        requestInput.setLineWrap(false);

        JScrollPane requestScroll = new JScrollPane(requestInput);
        requestScroll.setBorder(BorderFactory.createTitledBorder("HTTP Request"));

        JPanel outputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        signatureOut.setEditable(false);

        c.gridx = 0; c.gridy = 0; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        outputPanel.add(new JLabel("Authorization (value):"), c);

        c.gridx = 1; c.gridy = 0; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        outputPanel.add(signatureOut, c);

        debugOut.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        debugOut.setEditable(false);
        debugOut.setLineWrap(false);

        JScrollPane debugScroll = new JScrollPane(debugOut);
        debugScroll.setBorder(BorderFactory.createTitledBorder("Debug / Canonicalization"));

        c.gridx = 0; c.gridy = 1; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 1.0;
        c.fill = GridBagConstraints.BOTH;
        outputPanel.add(debugScroll, c);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestScroll, outputPanel);
        split.setResizeWeight(0.55);

        content.add(split, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(calcButton);
        buttons.add(clearButton);
        buttons.add(closeButton);
        content.add(buttons, BorderLayout.SOUTH);

        clearButton.addActionListener(e -> {
            requestInput.setText("");
            signatureOut.setText("");
            debugOut.setText("");
        });

        closeButton.addActionListener(e -> dispose());

        calcButton.addActionListener(e -> onCalculate());

        pack();
        setMinimumSize(new Dimension(920, 740));
        setLocationRelativeTo(parent);
    }

    private void onCalculate() {
        Profile p = store.selected();
        if (p == null) {
            showError("No profile selected.");
            return;
        }

        String raw = requestInput.getText();
        if (raw == null || raw.trim().isEmpty()) {
            showError("Paste an HTTP request first.");
            return;
        }

        calcButton.setEnabled(false);
        debugOut.setText("Calculating...");
        signatureOut.setText("");

        SwingWorker<OciSignatureCalculator.Result, Void> worker = new SwingWorker<>() {
            @Override
            protected OciSignatureCalculator.Result doInBackground() {
                OciSignatureCalculator.ParsedRequest parsed =
                        OciSignatureCalculator.parseRawHttpRequest(raw);
                return OciSignatureCalculator.compute(p, parsed);
            }

            @Override
            protected void done() {
                try {
                    OciSignatureCalculator.Result result = get();
                    signatureOut.setText(result.authorizationHeaderValue);
                    debugOut.setText(result.debugText);

                    try {
                        if (api != null) {
                            api.logging().logToOutput("[OCI Signer] Signature Calculator: computed signature using profile: " + p.name());
                        }
                    } catch (Exception ignored) {}
                } catch (Exception ex) {
                    signatureOut.setText("");
                    debugOut.setText("");
                    showError(ex.getMessage() == null ? ex.toString() : ex.getMessage());

                    try {
                        if (api != null) {
                            api.logging().logToError("[OCI Signer] Signature Calculator error: " + ex);
                        }
                    } catch (Exception ignored) {}
                } finally {
                    calcButton.setEnabled(true);
                }
            }
        };

        worker.execute();
    }

    private void showError(String msg) {
        JOptionPane.showMessageDialog(
                this,
                msg,
                "Signature Calculator",
                JOptionPane.ERROR_MESSAGE
        );
    }
}
