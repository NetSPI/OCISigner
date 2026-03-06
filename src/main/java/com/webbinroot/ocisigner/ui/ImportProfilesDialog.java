package com.webbinroot.ocisigner.ui;

import burp.api.montoya.MontoyaApi;
import com.webbinroot.ocisigner.model.AuthType;
import com.webbinroot.ocisigner.model.Profile;
import com.webbinroot.ocisigner.model.ProfileStore;
import com.webbinroot.ocisigner.model.SigningMode;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Minimal AWS-Signer-like import dialog.
 *
 * v1: Source buttons: Auto + File
 * v1: Select buttons: All + None
 *
 * Parses OCI CLI config INI files (e.g. ~/.oci/config):
 *
 * [DEFAULT]
 * user=...
 * fingerprint=...
 * tenancy=...
 * region=...
 * key_file=...
 */
public class ImportProfilesDialog extends JDialog {

    private final MontoyaApi api;
    private final ProfileStore store;

    private final JButton autoBtn = new JButton("Auto");
    private final JButton fileBtn = new JButton("File");
    private final JButton allBtn = new JButton("All");
    private final JButton noneBtn = new JButton("None");

    private final JButton okBtn = new JButton("OK");
    private final JButton cancelBtn = new JButton("Cancel");

    private final ImportTableModel tableModel = new ImportTableModel();
    private final JTable table = new JTable(tableModel);
    private final JLabel autoSearchHelp = new JLabel("Auto checks: ~/.oci/config");

    // Track last loaded INI file so we can default session-token config settings.
    private File lastLoadedFile = null;

    /**
     * Dialog to import OCI profiles from a config file.
     * Example input: ~/.oci/config -> selectable rows
     */
    public ImportProfilesDialog(Window parent, MontoyaApi api, ProfileStore store) {
        super(parent, "Import Signing Profiles", ModalityType.APPLICATION_MODAL);
        this.api = api;
        this.store = store;

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setPreferredSize(new Dimension(860, 420));

        JPanel root = new JPanel(new BorderLayout(10, 10));
        root.setBorder(new EmptyBorder(10, 10, 10, 10));

        // -------------------------
        // Header controls (LEFT aligned)
        // -------------------------
        JPanel sourceBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        sourceBtns.add(autoBtn);
        sourceBtns.add(fileBtn);

        JPanel selectBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        selectBtns.add(allBtn);
        selectBtns.add(noneBtn);

        JPanel headerRow = new JPanel(new GridBagLayout());
        GridBagConstraints hc = new GridBagConstraints();
        hc.insets = new Insets(2, 2, 2, 2);
        hc.anchor = GridBagConstraints.WEST;
        hc.gridy = 0;

        hc.gridx = 0;
        headerRow.add(new JLabel("Source"), hc);

        hc.gridx = 1;
        headerRow.add(sourceBtns, hc);

        // Spacer to push "Select" group to the right while keeping left alignment
        hc.gridx = 2;
        hc.weightx = 1.0;
        hc.fill = GridBagConstraints.HORIZONTAL;
        headerRow.add(Box.createHorizontalGlue(), hc);

        hc.gridx = 3;
        hc.weightx = 0;
        hc.fill = GridBagConstraints.NONE;
        headerRow.add(new JLabel("Select"), hc);

        hc.gridx = 4;
        headerRow.add(selectBtns, hc);

        autoSearchHelp.setFont(autoSearchHelp.getFont().deriveFont(Font.ITALIC));

        JPanel headerContainer = new JPanel();
        headerContainer.setLayout(new BoxLayout(headerContainer, BoxLayout.Y_AXIS));
        headerRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        autoSearchHelp.setAlignmentX(Component.LEFT_ALIGNMENT);
        headerContainer.add(headerRow);
        headerContainer.add(Box.createVerticalStrut(4));
        headerContainer.add(autoSearchHelp);

        root.add(headerContainer, BorderLayout.NORTH);

        // -------------------------
        // Table
        // -------------------------
        configureTable();
        JScrollPane scroll = new JScrollPane(table);
        root.add(scroll, BorderLayout.CENTER);

        // -------------------------
        // Bottom buttons
        // -------------------------
        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        bottom.add(okBtn);
        bottom.add(cancelBtn);
        root.add(bottom, BorderLayout.SOUTH);

        setContentPane(root);
        pack();

        // -------------------------
        // Wire buttons
        // -------------------------
        autoBtn.addActionListener(e -> onAuto());
        fileBtn.addActionListener(e -> onFile());
        allBtn.addActionListener(e -> tableModel.setAllSelected(true));
        noneBtn.addActionListener(e -> tableModel.setAllSelected(false));

        okBtn.addActionListener(e -> onOk());
        cancelBtn.addActionListener(e -> dispose());

        // Important fix:
        // Do NOT run Auto on open. Only run when the user clicks Auto.
        // (No "loadFromAutoIfExists(...)" here.)
    }

    private void configureTable() {
        table.setFillsViewportHeight(true);
        table.setRowSelectionAllowed(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Column widths
        TableColumn importCol = table.getColumnModel().getColumn(0);
        importCol.setPreferredWidth(60);
        importCol.setMaxWidth(80);

        table.getColumnModel().getColumn(1).setPreferredWidth(140); // Name
        table.getColumnModel().getColumn(2).setPreferredWidth(260); // User
        table.getColumnModel().getColumn(3).setPreferredWidth(260); // Tenancy
        table.getColumnModel().getColumn(4).setPreferredWidth(110); // Region
        table.getColumnModel().getColumn(5).setPreferredWidth(260); // Key file
    }

    private void onAuto() {
        if (!loadFromAutoIfExists(true)) {
            JOptionPane.showMessageDialog(
                    this,
                    "No OCI config found at ~/.oci/config.",
                    "Import",
                    JOptionPane.INFORMATION_MESSAGE
            );
        }
    }

    private boolean loadFromAutoIfExists(boolean log) {
        // OCI CLI default: ~/.oci/config
        String home = System.getProperty("user.home");
        if (home == null || home.isBlank()) return false;

        Path p = Path.of(home, ".oci", "config");
        if (!Files.isRegularFile(p)) return false;

        try {
            loadIniFile(p.toFile(), log ? "Auto" : null);
            return true;
        } catch (Exception ex) {
            if (log && api != null) {
                api.logging().logToOutput("[OCI Signer] Auto import failed: " + ex);
            }
            return false;
        }
    }

    private void onFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select OCI config file");
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        int res = chooser.showOpenDialog(this);
        if (res != JFileChooser.APPROVE_OPTION) return;

        File f = chooser.getSelectedFile();
        if (f == null || !f.isFile()) return;

        try {
            loadIniFile(f, "File");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "Failed to parse file: " + ex.getMessage(),
                    "Import",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private void loadIniFile(File file, String sourceName) throws Exception {
        lastLoadedFile = file;
        Map<String, Map<String, String>> sections = parseIni(file);
        List<ImportCandidate> candidates = new ArrayList<>();

        for (Map.Entry<String, Map<String, String>> e : sections.entrySet()) {
            String section = e.getKey();
            Map<String, String> kv = e.getValue();

            ImportCandidate c = new ImportCandidate();
            c.section = section;
            c.user = kv.getOrDefault("user", "");
            c.tenancy = kv.getOrDefault("tenancy", "");
            c.fingerprint = kv.getOrDefault("fingerprint", "");
            c.region = kv.getOrDefault("region", "");

            // OCI uses key_file in config
            c.keyFile = kv.getOrDefault("key_file", "");

            // Aliases (people do weird stuff)
            if (c.keyFile.isBlank()) c.keyFile = kv.getOrDefault("private_key_file", "");
            if (c.keyFile.isBlank()) c.keyFile = kv.getOrDefault("keyfile", "");

            // If section is empty, skip it
            if (c.user.isBlank() && c.tenancy.isBlank() && c.fingerprint.isBlank() && c.keyFile.isBlank()) {
                continue;
            }

            candidates.add(c);
        }

        tableModel.setCandidates(candidates);

        if (sourceName != null && api != null) {
            api.logging().logToOutput("[OCI Signer] Import dialog loaded " + candidates.size()
                    + " profile(s) from " + sourceName + ": " + file.getAbsolutePath());
        }
    }

    private void onOk() {
        List<ImportCandidate> selected = tableModel.selectedCandidates();
        if (selected.isEmpty()) {
            dispose();
            return;
        }

        Profile first = null;

        for (ImportCandidate c : selected) {
            Profile p = store.addImportedProfile(uniqueProfileName(c.section));

            // Credentials
            p.setAuthType(AuthType.API_KEY);
            p.signingMode = SigningMode.SDK;

            // Values
            p.userOcid = safe(c.user);
            p.tenancyOcid = safe(c.tenancy);
            p.fingerprint = safe(c.fingerprint);
            p.privateKeyPath = safe(c.keyFile);

            // Helpers
            p.region = safe(c.region);

            // Session token auth uses the same config file + profile name.
            if (lastLoadedFile != null) {
                p.configFilePath = lastLoadedFile.getAbsolutePath();
                p.configProfileName = c.section;
            }

            if (first == null) first = p;
        }

        if (first != null) {
            store.select(first);
        }

        store.saveProfiles();
        dispose();
    }

    private String uniqueProfileName(String base) {
        String b = (base == null || base.isBlank()) ? "DEFAULT" : base.trim();

        // Avoid collisions by adding (1), (2)...
        String name = b;
        int i = 1;
        while (store.byName(name).isPresent()) {
            name = b + "(" + i + ")";
            i++;
        }
        return name;
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }

    /**
     * Very small INI parser:
     *  - Supports [SECTION]
     *  - Supports key=value
     *  - Ignores comments starting with # or ;
     */
    private static Map<String, Map<String, String>> parseIni(File f) throws Exception {
        Map<String, Map<String, String>> out = new LinkedHashMap<>();

        String current = "DEFAULT";
        out.put(current, new LinkedHashMap<>());

        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {

            String line;
            while ((line = br.readLine()) != null) {
                String s = line.trim();
                if (s.isEmpty()) continue;
                if (s.startsWith("#") || s.startsWith(";")) continue;

                if (s.startsWith("[") && s.endsWith("]") && s.length() > 2) {
                    current = s.substring(1, s.length() - 1).trim();
                    if (current.isEmpty()) current = "DEFAULT";
                    out.putIfAbsent(current, new LinkedHashMap<>());
                    continue;
                }

                int idx = s.indexOf('=');
                if (idx <= 0) continue;

                String k = s.substring(0, idx).trim().toLowerCase(Locale.ROOT);
                String v = s.substring(idx + 1).trim();

                // Strip surrounding quotes if present
                if ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'"))) {
                    if (v.length() >= 2) v = v.substring(1, v.length() - 1);
                }

                out.get(current).put(k, v);
            }
        }

        return out;
    }

    // ---------------- Table model ----------------

    private static final class ImportCandidate {
        boolean selected = true;
        String section;
        String user;
        String tenancy;
        String fingerprint;
        String region;
        String keyFile;
    }

    private static final class ImportTableModel extends AbstractTableModel {

        private final String[] cols = new String[]{
                "Import",
                "Name",
                "User OCID",
                "Tenancy OCID",
                "Region",
                "Key File"
        };

        private final List<ImportCandidate> rows = new ArrayList<>();

        /**
         * Replace the table contents.
         * Example input: list of ImportCandidate rows.
         */
        public void setCandidates(List<ImportCandidate> candidates) {
            rows.clear();
            if (candidates != null) rows.addAll(candidates);
            fireTableDataChanged();
        }

        /**
         * Select/unselect all rows.
         * Example input: true -> all selected
         */
        public void setAllSelected(boolean val) {
            for (ImportCandidate r : rows) {
                r.selected = val;
            }
            fireTableDataChanged();
        }

        /**
         * Return only selected candidates.
         */
        public List<ImportCandidate> selectedCandidates() {
            List<ImportCandidate> out = new ArrayList<>();
            for (ImportCandidate r : rows) {
                if (r.selected) out.add(r);
            }
            return out;
        }

        @Override
        public int getRowCount() { return rows.size(); }

        @Override
        public int getColumnCount() { return cols.length; }

        @Override
        public String getColumnName(int column) { return cols[column]; }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Boolean.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ImportCandidate r = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.selected;
                case 1 -> r.section;
                case 2 -> r.user;
                case 3 -> r.tenancy;
                case 4 -> r.region;
                case 5 -> r.keyFile;
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex != 0) return;
            ImportCandidate r = rows.get(rowIndex);
            r.selected = Boolean.TRUE.equals(aValue);
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }
}
