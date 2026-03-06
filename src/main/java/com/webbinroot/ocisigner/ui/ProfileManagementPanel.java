package com.webbinroot.ocisigner.ui;

import burp.api.montoya.MontoyaApi;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.ProfileStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.Objects;

public class ProfileManagementPanel {

    private final JPanel root;
    private final DefaultListModel<Profile> listModel = new DefaultListModel<>();
    private final JList<Profile> profileList = new JList<>(listModel);

    /**
     * Build the profile management panel (list + add/copy/import).
     * Example output: a Swing panel with profile list and buttons.
     */
    public ProfileManagementPanel(MontoyaApi api, ProfileStore store, GlobalSettingsPanel global) {
        GlobalSettingsPanel globalPanel = Objects.requireNonNull(global);

        root = new JPanel(new GridBagLayout());
        root.setBorder(new EmptyBorder(2, 2, 2, 6));

        root.setPreferredSize(new Dimension(320, 0));
        root.setMinimumSize(new Dimension(240, 0));

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(2, 4, 2, 4);
        c.anchor = GridBagConstraints.NORTHWEST;

        JLabel header = UiStyles.sectionHeader("Profile Management");
        c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        root.add(header, c);

        JLabel desc = new JLabel("Manage profiles which provide OCI credentials");
        c.gridy = 1;
        root.add(desc, c);

        JPanel buttons = new JPanel();
        buttons.setLayout(new BoxLayout(buttons, BoxLayout.Y_AXIS));
        buttons.setBorder(new EmptyBorder(0, 0, 0, 0));

        JButton add = new JButton("Add");
        JButton delete = new JButton("Delete");
        JButton copy = new JButton("Copy");
        JButton imp = new JButton("Import");

        Dimension btnSize = new Dimension(88, 24);
        for (JButton b : new JButton[]{add, delete, copy, imp}) {
            b.setPreferredSize(btnSize);
            b.setMaximumSize(btnSize);
            b.setMinimumSize(btnSize);
            b.setAlignmentX(Component.LEFT_ALIGNMENT);
            buttons.add(b);
            buttons.add(Box.createVerticalStrut(6));
        }

        profileList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scroll = new JScrollPane(profileList,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setPreferredSize(new Dimension(170, 150));
        scroll.setMinimumSize(new Dimension(150, 120));

        c.gridwidth = 1; c.gridy = 2;

        c.gridx = 0; c.weightx = 0; c.weighty = 0; c.fill = GridBagConstraints.NONE;
        root.add(buttons, c);

        c.gridx = 1; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL;
        root.add(scroll, c);

        c.gridx = 0; c.gridy = 3; c.gridwidth = 2;
        c.weightx = 1.0; c.weighty = 1.0; c.fill = GridBagConstraints.BOTH;
        root.add(Box.createGlue(), c);

        // Populate once
        refresh(store);
        if (store.selected() != null) {
            profileList.setSelectedValue(store.selected(), true);
        }
        globalPanel.refreshProfiles(store);

        // Selection
        profileList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                Profile sel = profileList.getSelectedValue();
                if (sel != null && store.selected() != sel) {
                    store.select(sel);
                    store.changed("ui.profileSelected", sel);
                    globalPanel.refreshProfiles(store);
                }
            }
        });

        add.addActionListener(e -> {
            Profile p = store.addNew();
            refresh(store);
            profileList.setSelectedValue(p, true);
            globalPanel.refreshProfiles(store);
        });

        delete.addActionListener(e -> {
            Profile sel = profileList.getSelectedValue();
            if (sel != null) {
                store.delete(sel);
                refresh(store);
                if (store.selected() != null) {
                    profileList.setSelectedValue(store.selected(), true);
                }
                globalPanel.refreshProfiles(store);
            }
        });

        copy.addActionListener(e -> {
            Profile sel = profileList.getSelectedValue();
            if (sel != null) {
                Profile cpy = store.copy(sel);
                refresh(store);
                profileList.setSelectedValue(cpy, true);
                globalPanel.refreshProfiles(store);
            }
        });

        // Import dialog (AWS-signer-like) — unchanged
        imp.addActionListener(e -> {
            ImportProfilesDialog dlg = new ImportProfilesDialog(
                    SwingUtilities.getWindowAncestor(root),
                    api,
                    store
            );
            dlg.setLocationRelativeTo(root);
            dlg.setVisible(true);

            // After dialog closes, refresh
            refresh(store);
            if (store.selected() != null) {
                profileList.setSelectedValue(store.selected(), true);
            }
            globalPanel.refreshProfiles(store);
        });

        // IMPORTANT: filter store events so typing into text fields doesn't refresh the list and freeze Burp.
        store.registerListener(msg -> {
            if (msg == null) return;
            if (msg.contains("selected_profile")
                    || msg.contains("profile_added")
                    || msg.contains("profile_deleted")
                    || msg.contains("profile_copied")
                    || msg.contains("profile_imported")) {
                SwingUtilities.invokeLater(() -> {
                    refresh(store);
                    if (store.selected() != null) {
                        profileList.setSelectedValue(store.selected(), true);
                    }
                    globalPanel.refreshProfiles(store);
                });
            }
        });
    }

    /**
     * Refresh the list UI from the store.
     * Example input: store.all() -> list model updated
     */
    public void refresh(ProfileStore store) {
        listModel.clear();
        for (Profile p : store.all()) {
            listModel.addElement(p);
        }
    }

    /**
     * Return the root Swing component for embedding in the tab.
     */
    public JComponent getRoot() {
        return root;
    }
}
