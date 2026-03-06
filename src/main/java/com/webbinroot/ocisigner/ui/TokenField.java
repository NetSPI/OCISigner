package com.webbinroot.ocisigner.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Reusable multiline token input with Reveal/Hide toggle (and optional Browse button).
 * Stores the raw token value in memory and masks the UI when hidden.
 */
public final class TokenField {

    private final JTextArea area;
    private final JToggleButton revealButton;
    private final JButton browseButton;
    private final JPanel row;
    private String tokenValue = "";
    private boolean suppress = false;
    private Runnable onTokenEdited;

    public TokenField(int rows, boolean withBrowse, boolean defaultReveal) {
        area = new JTextArea(rows, 60);
        area.setLineWrap(true);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        JScrollPane scroll = new JScrollPane(area);
        scroll.setBorder(UIManager.getBorder("TextField.border"));
        scroll.setPreferredSize(new Dimension(300, rows <= 4 ? 80 : 100));
        scroll.setMinimumSize(new Dimension(300, rows <= 4 ? 60 : 80));

        revealButton = new JToggleButton(defaultReveal ? "Hide" : "Reveal");
        revealButton.setSelected(defaultReveal);

        if (withBrowse) {
            browseButton = new JButton("Browse…");
        } else {
            browseButton = null;
        }

        JPanel buttons = new JPanel(new GridLayout(withBrowse ? 2 : 1, 1, 0, 4));
        buttons.setOpaque(false);
        if (browseButton != null) {
            buttons.add(browseButton);
        }
        buttons.add(revealButton);

        row = new JPanel(new BorderLayout(6, 0));
        row.setOpaque(false);
        row.add(scroll, BorderLayout.CENTER);
        row.add(buttons, BorderLayout.EAST);

        revealButton.addActionListener(e -> {
            revealButton.setText(revealButton.isSelected() ? "Hide" : "Reveal");
            updateDisplay();
        });

        area.getDocument().addDocumentListener(SimpleDocListener.onChange(() -> {
            if (suppress) return;
            if (!revealButton.isSelected()) return;
            tokenValue = area.getText();
            if (onTokenEdited != null) onTokenEdited.run();
        }));

        updateDisplay();
    }

    public JPanel row() {
        return row;
    }

    public JButton browseButton() {
        return browseButton;
    }

    public void setOnTokenEdited(Runnable onTokenEdited) {
        this.onTokenEdited = onTokenEdited;
    }

    public void setTokenValue(String tokenValue) {
        this.tokenValue = tokenValue == null ? "" : tokenValue;
        updateDisplay();
    }

    public String tokenValue() {
        return tokenValue == null ? "" : tokenValue;
    }

    public void clear() {
        setTokenValue("");
    }

    public void setEnabled(boolean enabled) {
        area.setEnabled(enabled);
        revealButton.setEnabled(enabled);
        if (browseButton != null) browseButton.setEnabled(enabled);
    }

    public void setTextBackground(Color color) {
        area.setBackground(color);
    }

    private void updateDisplay() {
        boolean reveal = revealButton.isSelected();
        area.setEditable(reveal);
        suppress = true;
        if (tokenValue == null || tokenValue.isBlank()) {
            area.setText("");
        } else {
            area.setText(reveal ? tokenValue : mask(tokenValue));
        }
        suppress = false;
        try {
            area.setCaretPosition(0);
        } catch (Exception ignored) {}
    }

    private static String mask(String token) {
        if (token == null || token.isEmpty()) return "";
        return "*".repeat(token.length());
    }
}
