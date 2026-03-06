package com.webbinroot.ocisigner.util;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Shared HTTP debug formatting helpers (request dumps + header formatting).
 */
public final class OciHttpDebug {

    public static final int DEFAULT_MAX_BODY = 4096;

    private OciHttpDebug() {}

    public static String dumpMontoyaRequest(HttpRequest req) {
        return dumpMontoyaRequest(req, DEFAULT_MAX_BODY);
    }

    public static String dumpMontoyaRequest(HttpRequest req, int maxBodyBytes) {
        if (req == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append(req.method()).append(" ").append(req.path()).append(" ").append(req.httpVersion()).append("\n");
        for (HttpHeader h : req.headers()) {
            sb.append(h.name()).append(": ").append(h.value()).append("\n");
        }
        sb.append("\n");
        byte[] b = (req.body() == null) ? null : req.body().getBytes();
        if (b != null && b.length > 0) {
            int len = b.length;
            int max = Math.min(len, maxBodyBytes);
            sb.append(new String(b, 0, max, StandardCharsets.UTF_8));
            if (len > maxBodyBytes) {
                sb.append("\n...[truncated ").append(len - maxBodyBytes).append(" bytes]");
            }
        }
        return sb.toString();
    }

    public static String formatHeaderMultimap(Map<String, List<String>> headers) {
        StringBuilder sb = new StringBuilder();
        if (headers == null) return "";
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            sb.append("  ").append(e.getKey()).append(": ");
            List<String> v = e.getValue();
            if (v != null && !v.isEmpty()) {
                sb.append(String.join(", ", v));
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    public static String formatHeaderMap(Map<String, String> headers) {
        StringBuilder sb = new StringBuilder();
        if (headers == null) return "";
        for (Map.Entry<String, String> e : headers.entrySet()) {
            sb.append("  ").append(e.getKey()).append(": ").append(e.getValue()).append("\n");
        }
        return sb.toString();
    }
}
