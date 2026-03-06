package com.webbinroot.ocisigner.ui;

import burp.api.montoya.MontoyaApi;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.ProfileStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class GlobalSettingsPanel {

    private final JPanel root;

    private final JCheckBox signingEnabled = new JCheckBox("Signing Enabled");
    private final JComboBox<Profile> alwaysSignWith = new JComboBox<>();
    private final JComboBox<String> logLevel = new JComboBox<>(new String[]{"Error", "Info", "Debug"});

    private boolean suppressEvents = false;

    /**
     * Build the global settings panel (signing enabled, always sign with, log level).
     */
    public GlobalSettingsPanel(MontoyaApi api, ProfileStore store) {
        root = new JPanel(new GridBagLayout());
        root.setBorder(new EmptyBorder(2, 2, 6, 2));

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(2, 4, 2, 4);
        c.anchor = GridBagConstraints.WEST;

        JLabel header = UiStyles.sectionHeader("Global Settings");
        c.gridx = 0; c.gridy = 0; c.gridwidth = 6; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(header, c);

        JLabel help = new JLabel("Change extension behavior. Set Always Sign With to force signing of all requests with the specified profile credentials.");
        c.gridy = 1;
        root.add(help, c);

        c.gridwidth = 1; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        c.gridy = 2;

        c.gridx = 0;
        root.add(signingEnabled, c);

        c.gridx = 1;
        root.add(new JLabel("Always Sign With:"), c);

        c.gridx = 2; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(alwaysSignWith, c);

        c.gridx = 3; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        root.add(new JLabel("Log Level:"), c);

        c.gridx = 4;
        root.add(logLevel, c);

        // Render null as italic "No Profile"
        alwaysSignWith.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                JLabel lbl = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value == null) {
                    lbl.setText("No Profile");
                    lbl.setFont(lbl.getFont().deriveFont(Font.ITALIC));
                }
                return lbl;
            }
        });

        suppressEvents = true;
        try {
            signingEnabled.setSelected(store.signingEnabled());
            logLevel.setSelectedItem(store.logLevel());
            refreshProfiles(store);
        } finally {
            suppressEvents = false;
        }

        signingEnabled.addActionListener(e -> {
            if (suppressEvents) return;
            store.setSigningEnabled(signingEnabled.isSelected());
        });

        logLevel.addActionListener(e -> {
            if (suppressEvents) return;
            store.setLogLevel((String) logLevel.getSelectedItem());
        });

        alwaysSignWith.addActionListener(e -> {
            if (suppressEvents) return;
            Profile p = (Profile) alwaysSignWith.getSelectedItem();
            store.setAlwaysSignWith(p); // null => No Profile
        });

        store.registerListener(evt -> SwingUtilities.invokeLater(() -> {
            if (evt == null) return;

            boolean refresh =
                    evt.contains("profile_added")
                            || evt.contains("profile_deleted")
                            || evt.contains("profile_copied")
                            || evt.contains("global_always_sign_with")
                            || evt.contains("selected_profile")
                            || evt.contains("global_signing_enabled")
                            || evt.contains("global_log_level");

            suppressEvents = true;
            try {
                if (evt.contains("global_signing_enabled")) {
                    signingEnabled.setSelected(store.signingEnabled());
                }
                if (evt.contains("global_log_level")) {
                    logLevel.setSelectedItem(store.logLevel());
                }
                if (refresh) {
                    refreshProfiles(store);
                }
            } finally {
                suppressEvents = false;
            }
        }));
    }

    /**
     * Refresh the "Always Sign With" dropdown from the store.
     */
    public void refreshProfiles(ProfileStore store) {
        boolean prev = suppressEvents;
        suppressEvents = true;
        try {
            alwaysSignWith.removeAllItems();
            alwaysSignWith.addItem(null); // No Profile
            for (Profile p : store.all()) {
                alwaysSignWith.addItem(p);
            }
            alwaysSignWith.setSelectedItem(store.alwaysSignWith());
        } finally {
            suppressEvents = prev;
        }
    }

    /**
     * Return the root Swing component for embedding in the tab.
     */
    public JComponent getRoot() {
        return root;
    }
}
