package com.webbinroot.ocisigner.model;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Manual signing settings (Custom mode).
 */
public class ManualSigningSettings {

    // Signing algorithm (future custom mode). OCI commonly uses rsa-sha256.
    public String algorithm = "rsa-sha256";

    // Which "headers" are included in the signing string (some are pseudo-headers).
    public boolean signRequestTarget = true;  // (request-target) pseudo-header
    public boolean signDate = true;
    public boolean signHost = true;

    // Body-related headers (default true for typical OCI behavior)
    public boolean signXContentSha256 = true;
    public boolean signContentType = true;
    public boolean signContentLength = true;

    // Deviations / custom behaviors
    public boolean allowGetWithBody = false;
    public boolean allowDeleteWithBody = false;

    public boolean addMissingDate = true;
    public boolean addMissingHost = true;
    public boolean computeMissingXContentSha256 = true;
    public boolean computeMissingContentLength = true;

    // Extra headers (one per line)
    public String extraSignedHeaders = "";

    // -----------------------------
    // HMAC settings (only used for hmac-* algorithms)
    // -----------------------------
    public enum HmacKeyMode { TEXT, FILE }
    public HmacKeyMode hmacKeyMode = HmacKeyMode.TEXT;

    /**
     * If TEXT mode:
     * - If starts with "base64:" we treat remainder as base64 bytes
     * - Else we treat it as UTF-8 bytes
     */
    public String hmacKeyText = "";

    /** If FILE mode: path to file containing raw bytes or a base64 string. */
    public String hmacKeyFilePath = "";

    /**
     * Deep copy settings (safe for UI edits).
     * Example output: a new ManualSigningSettings with identical values.
     */
    public ManualSigningSettings copy() {
        ManualSigningSettings c = new ManualSigningSettings();
        c.algorithm = this.algorithm;

        c.signRequestTarget = this.signRequestTarget;
        c.signDate = this.signDate;
        c.signHost = this.signHost;

        c.signXContentSha256 = this.signXContentSha256;
        c.signContentType = this.signContentType;
        c.signContentLength = this.signContentLength;

        c.allowGetWithBody = this.allowGetWithBody;
        c.allowDeleteWithBody = this.allowDeleteWithBody;
        c.addMissingDate = this.addMissingDate;
        c.addMissingHost = this.addMissingHost;
        c.computeMissingXContentSha256 = this.computeMissingXContentSha256;
        c.computeMissingContentLength = this.computeMissingContentLength;

        c.extraSignedHeaders = this.extraSignedHeaders;

        c.hmacKeyMode = this.hmacKeyMode;
        c.hmacKeyText = this.hmacKeyText;
        c.hmacKeyFilePath = this.hmacKeyFilePath;

        return c;
    }

    /**
     * Defaults that match OCI SDK signing behavior.
     * Example output: rsa-sha256 + date/host/(request-target) + body headers.
     */
    public static ManualSigningSettings defaultsLikeSdk() {
        ManualSigningSettings d = new ManualSigningSettings();

        d.algorithm = "rsa-sha256";

        d.signRequestTarget = true;
        d.signDate = true;
        d.signHost = true;

        d.signXContentSha256 = true;
        d.signContentType = true;
        d.signContentLength = true;

        d.allowGetWithBody = false;
        d.allowDeleteWithBody = false;

        d.addMissingDate = true;
        d.addMissingHost = true;
        d.computeMissingXContentSha256 = true;
        d.computeMissingContentLength = true;

        d.extraSignedHeaders = "";

        // HMAC defaults (unused unless algorithm is hmac-*)
        d.hmacKeyMode = HmacKeyMode.TEXT;
        d.hmacKeyText = "";
        d.hmacKeyFilePath = "";

        return d;
    }

    /**
     * Parse extraSignedHeaders into a normalized list.
     * Example input: "opc-request-id\nx-custom"
     * Example output: ["opc-request-id","x-custom"]
     */
    public List<String> extraHeadersList() {
        if (extraSignedHeaders == null || extraSignedHeaders.trim().isEmpty()) return List.of();
        String[] lines = extraSignedHeaders.split("\\r?\\n");
        List<String> out = new ArrayList<>();
        for (String ln : lines) {
            if (ln == null) continue;
            String v = ln.trim();
            if (v.isEmpty()) continue;
            out.add(v.toLowerCase());
        }
        return out;
    }

    /**
     * Build the header signing order preview.
     * Example output: ["(request-target)","date","host",...]
     */
    public List<String> defaultHeaderOrderPreview() {
        List<String> headers = new ArrayList<>();
        if (signRequestTarget) headers.add("(request-target)");
        if (signDate) headers.add("date");
        if (signHost) headers.add("host");

        if (signXContentSha256) headers.add("x-content-sha256");
        if (signContentType) headers.add("content-type");
        if (signContentLength) headers.add("content-length");

        headers.addAll(extraHeadersList());
        return headers;
    }

    /**
     * True if algorithm starts with "hmac-".
     */
    public boolean isHmacAlgorithm() {
        String a = (algorithm == null) ? "" : algorithm.trim().toLowerCase();
        return a.startsWith("hmac-");
    }

    /**
     * Resolve the HMAC key bytes from settings.
     * (File reading is done in the signer so we don't add IO dependencies here.)
     */
    public static byte[] parseHmacKeyText(String text) {
        if (text == null) text = "";
        String t = text.trim();
        if (t.isEmpty()) return null;

        if (t.regionMatches(true, 0, "base64:", 0, "base64:".length())) {
            String b64 = t.substring("base64:".length()).trim();
            if (b64.isEmpty()) return null;
            return Base64.getDecoder().decode(b64);
        }
        return t.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Compact settings summary for logs.
     * Example output: ManualSigningSettings{algorithm=rsa-sha256, headers=...}
     */
    public String toLogString() {
        return "ManualSigningSettings{" +
                "algorithm=" + algorithm +
                ", headers=" + String.join(" ", defaultHeaderOrderPreview()) +
                ", allowGetWithBody=" + allowGetWithBody +
                ", allowDeleteWithBody=" + allowDeleteWithBody +
                ", addMissingDate=" + addMissingDate +
                ", addMissingHost=" + addMissingHost +
                ", computeMissingXContentSha256=" + computeMissingXContentSha256 +
                ", computeMissingContentLength=" + computeMissingContentLength +
                ", extraHeadersCount=" + extraHeadersList().size() +
                ", hmacKeyMode=" + hmacKeyMode +
                "}";
    }
}
