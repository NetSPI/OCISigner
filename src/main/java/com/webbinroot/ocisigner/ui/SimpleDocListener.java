package com.webbinroot.ocisigner.ui;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class SimpleDocListener {
    /**
     * Callback invoked on any document change.
     */
    public interface Callback { void run(); }

    /**
     * Create a DocumentListener that invokes cb on any change.
     * Example input: () -> markDirty()
     */
    public static DocumentListener onChange(Callback cb) {
        return new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { cb.run(); }
            @Override public void removeUpdate(DocumentEvent e) { cb.run(); }
            @Override public void changedUpdate(DocumentEvent e) { cb.run(); }
        };
    }
}
