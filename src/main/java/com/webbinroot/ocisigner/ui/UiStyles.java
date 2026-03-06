package com.webbinroot.ocisigner.ui;

import javax.swing.*;
import java.awt.*;

public class UiStyles {
    // AWS Signer-ish orange
    public static final Color AWS_ORANGE = new Color(217, 83, 25);

    /**
     * Create a styled section header label.
     * Example input: "Profile Configuration"
     */
    public static JLabel sectionHeader(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(AWS_ORANGE);
        l.setFont(l.getFont().deriveFont(Font.BOLD, l.getFont().getSize2D() + 3.0f));
        return l;
    }
}
