package com.webbinroot.ocisigner.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Small helper for building two-column GridBag forms.
 * Keeps row/column boilerplate out of panel classes.
 */
public final class FormGrid {

    private final JPanel panel;
    private final GridBagConstraints c;
    private int row = 0;

    public FormGrid(JPanel panel, Insets insets) {
        this.panel = panel;
        this.c = new GridBagConstraints();
        this.c.insets = insets;
        this.c.anchor = GridBagConstraints.WEST;
    }

    public void addLabelField(String label, Component field) {
        addLabelField(label, field, GridBagConstraints.HORIZONTAL, 1.0, 0.0);
    }

    public void addLabelField(String label,
                              Component field,
                              int fill,
                              double weightx,
                              double weighty) {
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 1;
        c.weightx = 0.0;
        c.weighty = 0.0;
        c.fill = GridBagConstraints.NONE;
        panel.add(new JLabel(label), c);

        c.gridx = 1;
        c.weightx = weightx;
        c.weighty = weighty;
        c.fill = fill;
        panel.add(field, c);

        row++;
    }

    public void addFullRow(Component comp) {
        addRow(comp, 2, GridBagConstraints.HORIZONTAL, 1.0, 0.0);
    }

    public void addRow(Component comp,
                       int gridwidth,
                       int fill,
                       double weightx,
                       double weighty) {
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = gridwidth;
        c.weightx = weightx;
        c.weighty = weighty;
        c.fill = fill;
        panel.add(comp, c);
        c.gridwidth = 1;
        row++;
    }
}
