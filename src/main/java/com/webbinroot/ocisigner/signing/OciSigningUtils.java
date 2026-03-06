package com.webbinroot.ocisigner.signing;

import burp.api.montoya.http.message.HttpHeader;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Shared normalization helpers for signing.
 */
public final class OciSigningUtils {

    private OciSigningUtils() {}

    /**
     * Normalize request-target (path + query) for signing.
     * Example input: "n/?compartmentId=..." -> "/n/?compartmentId=..."
     */
    public static String normalizeRequestTarget(String requestTarget) {
        String t = (requestTarget == null) ? "" : requestTarget.trim();
        if (t.isBlank()) return "/";
        if (!t.startsWith("/")) t = "/" + t;
        return t;
    }

    /**
     * Convert Montoya headers to a lower-case multimap.
     * Example input: ["Host: example.com", "Date: ..."]
     * Example output: {"host":["example.com"], "date":["..."]}
     */
    public static Map<String, List<String>> toHeaderMultimap(List<HttpHeader> headers) {
        Map<String, List<String>> mm = new LinkedHashMap<>();
        if (headers == null) return mm;
        for (HttpHeader h : headers) {
            String name = h.name();
            String value = h.value();
            if (name == null) continue;

            String k = name.toLowerCase(Locale.ROOT);
            mm.computeIfAbsent(k, x -> new ArrayList<>()).add(value == null ? "" : value);
        }
        return mm;
    }

    /**
     * Normalize an existing header multimap to lower-case keys.
     * Example input: {"Host":["example.com"]} -> {"host":["example.com"]}
     */
    public static Map<String, List<String>> toHeaderMultimap(Map<String, List<String>> headers) {
        Map<String, List<String>> mm = new LinkedHashMap<>();
        if (headers == null) return mm;
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey() == null) continue;
            String k = e.getKey().toLowerCase(Locale.ROOT);
            List<String> v = (e.getValue() == null) ? new ArrayList<>() : new ArrayList<>(e.getValue());
            mm.put(k, v);
        }
        return mm;
    }

    /**
     * Detect Object Storage PUT special-case operations:
     *  - PutObject:  /n/{ns}/b/{bucket}/o/{object}
     *  - UploadPart: /n/{ns}/b/{bucket}/u/{uploadId}/id/{partNum}
     */
    public static boolean isObjectStoragePutSpecial(String method, String host, String requestTarget) {
        if (method == null || !"PUT".equalsIgnoreCase(method.trim())) return false;

        String h = normalizeHost(host);
        if (h.isBlank() || !h.contains("objectstorage.")) return false;

        String path = normalizeRequestTarget(requestTarget);
        int q = path.indexOf('?');
        if (q >= 0) path = path.substring(0, q);
        String[] seg = path.split("/", -1);

        // /n/{ns}/b/{bucket}/o/{object}
        boolean putObject = seg.length >= 7
                && "n".equals(seg[1])
                && !isBlank(seg[2])
                && "b".equals(seg[3])
                && !isBlank(seg[4])
                && "o".equals(seg[5])
                && !isBlank(seg[6]);
        if (putObject) return true;

        // /n/{ns}/b/{bucket}/u/{uploadId}/id/{partNum}
        return seg.length >= 9
                && "n".equals(seg[1])
                && !isBlank(seg[2])
                && "b".equals(seg[3])
                && !isBlank(seg[4])
                && "u".equals(seg[5])
                && !isBlank(seg[6])
                && "id".equals(seg[7])
                && !isBlank(seg[8]);
    }

    private static String normalizeHost(String host) {
        if (host == null) return "";
        String h = host.trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("http://")) h = h.substring("http://".length());
        if (h.startsWith("https://")) h = h.substring("https://".length());
        int slash = h.indexOf('/');
        if (slash >= 0) h = h.substring(0, slash);
        int at = h.lastIndexOf('@');
        if (at >= 0) h = h.substring(at + 1);
        return h;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
