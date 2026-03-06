package com.webbinroot.ocisigner.ui;

import burp.api.montoya.MontoyaApi;
import com.webbinroot.ocisigner.model.ProfileStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class OciSignerTab {

    private final JPanel root;

    /**
     * Build the main OCISigner tab (left profiles, right configuration).
     */
    public OciSignerTab(MontoyaApi api, ProfileStore store) {
        root = new JPanel(new BorderLayout());
        root.setBorder(new EmptyBorder(6, 6, 6, 6));

        GlobalSettingsPanel global = new GlobalSettingsPanel(api, store);

        ProfileManagementPanel left = new ProfileManagementPanel(api, store, global);
        ProfileConfigurationPanel right = new ProfileConfigurationPanel(api, store);
        JScrollPane rightScroll = new JScrollPane(
                right.getRoot(),
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
        );
        rightScroll.setBorder(null);
        rightScroll.getVerticalScrollBar().setUnitIncrement(16);

        // Vertical divider between left and right (the only one)
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left.getRoot(), rightScroll);
        split.setResizeWeight(0.22);
        split.setDividerSize(6);
        split.setContinuousLayout(true);

        // Keep Profile Management from expanding too wide
        final int LEFT_MAX = 320;
        final int LEFT_MIN = 240;

        left.getRoot().setMinimumSize(new Dimension(LEFT_MIN, 0));
        left.getRoot().setPreferredSize(new Dimension(LEFT_MAX, 0));
        left.getRoot().setMaximumSize(new Dimension(LEFT_MAX, Integer.MAX_VALUE));

        // Start at the cap
        split.setDividerLocation(LEFT_MAX);

        // IMPORTANT: Guard against re-entrant divider events (can freeze the UI)
        final boolean[] adjusting = { false };

        split.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, evt -> {
            if (adjusting[0]) return;

            int loc = split.getDividerLocation();
            int clamped = loc;

            if (loc > LEFT_MAX) clamped = LEFT_MAX;
            else if (loc < LEFT_MIN) clamped = LEFT_MIN;

            if (clamped != loc) {
                adjusting[0] = true;
                try {
                    split.setDividerLocation(clamped);
                } finally {
                    adjusting[0] = false;
                }
            }
        });

        // Top: Global settings + one full-width horizontal rule
        JPanel top = new JPanel(new BorderLayout());
        top.add(global.getRoot(), BorderLayout.NORTH);
        top.add(new JSeparator(SwingConstants.HORIZONTAL), BorderLayout.SOUTH);

        root.add(top, BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);
    }

    /**
     * Return the root Swing component for registering as a Burp tab.
     */
    public JComponent getRoot() {
        return root;
    }
}
