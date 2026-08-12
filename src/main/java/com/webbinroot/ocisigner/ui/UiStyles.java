package com.webbinroot.ocisigner.ui;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.function.Consumer;

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

    /**
     * Wrap a field and a button into one row (field fills remaining space, button hugs the right edge).
     */
    public static JPanel rowWithButton(Component field, Component button) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setOpaque(false);
        row.add(field, BorderLayout.CENTER);
        row.add(button, BorderLayout.EAST);
        return row;
    }

    /**
     * Open a single-file "Open" chooser and, if the user picks a file,
     * hand its absolute path to onPicked. No-op on cancel or no selection.
     */
    public static void browseForFile(Component parent, String dialogTitle, Consumer<String> onPicked) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(dialogTitle);
        int result = fc.showOpenDialog(parent);
        if (result == JFileChooser.APPROVE_OPTION) {
            File f = fc.getSelectedFile();
            if (f != null) {
                onPicked.accept(f.getAbsolutePath());
            }
        }
    }
}
