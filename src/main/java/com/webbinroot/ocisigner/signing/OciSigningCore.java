package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.model.ManualSigningSettings;
import com.webbinroot.ocisigner.util.OciTokenUtils;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static com.webbinroot.ocisigner.signing.OciSigningUtils.BODY_ALLOWED;
import static com.webbinroot.ocisigner.signing.OciSigningUtils.first;
import static com.webbinroot.ocisigner.util.OciTokenUtils.isBlank;
import static com.webbinroot.ocisigner.util.OciTokenUtils.nz;

/**
 * Shared signing normalization and signing-string construction.
 *
 * This centralizes:
 *  - header normalization (lower-case keys)
 *  - optional host/date injection
 *  - body header derivation (x-content-sha256, content-length)
 *  - signing string assembly
 */
public final class OciSigningCore {

    public static final class Prepared {
        public final String methodUpper;
        public final String requestTarget;
        public final Map<String, List<String>> headers;
        public final Map<String, String> headersToApply;
        public final List<String> headersToSign;
        public final String signingString;
        public final boolean considerBody;

        private Prepared(String methodUpper,
                         String requestTarget,
                         Map<String, List<String>> headers,
                         Map<String, String> headersToApply,
                         List<String> headersToSign,
                         String signingString,
                         boolean considerBody) {
            this.methodUpper = methodUpper;
            this.requestTarget = requestTarget;
            this.headers = headers;
            this.headersToApply = headersToApply;
            this.headersToSign = headersToSign;
            this.signingString = signingString;
            this.considerBody = considerBody;
        }
    }

    private static final DateTimeFormatter RFC1123 = DateTimeFormatter.RFC_1123_DATE_TIME;

    private OciSigningCore() {}

    public static Prepared prepare(ManualSigningSettings settings,
                                   String method,
                                   String requestTarget,
                                   String uriHost,
                                   Map<String, List<String>> headersIn,
                                   byte[] bodyBytes,
                                   boolean objectStoragePut,
                                   boolean addDateIfSigning,
                                   String delegationToken) {

        // Example input:
        //   method="GET", requestTarget="/n/", headersIn={"host":["objectstorage..."]}
        // Example output:
        //   headersToSign=["date","(request-target)","host"], signingString built accordingly
        if (settings == null) settings = ManualSigningSettings.defaultsLikeSdk();

        String m = nz(method).toUpperCase(Locale.ROOT);
        if (m.isBlank()) throw new IllegalArgumentException("Missing HTTP method.");

        String target = OciSigningUtils.normalizeRequestTarget(requestTarget);

        Map<String, List<String>> headers = OciSigningUtils.toHeaderMultimap(headersIn);
        Map<String, String> apply = new LinkedHashMap<>();

        boolean hasBody = bodyBytes != null && bodyBytes.length > 0;
        boolean bodyAllowed = BODY_ALLOWED.contains(m)
                || (settings.allowGetWithBody && "GET".equals(m))
                || (settings.allowDeleteWithBody && "DELETE".equals(m));
        // OCI requires body headers for PUT/POST even when body is empty.
        boolean considerBody = bodyAllowed && (hasBody || "PUT".equals(m) || "POST".equals(m));
        byte[] effectiveBodyBytes = (bodyBytes == null) ? new byte[0] : bodyBytes;

        String hostVal = first(headers.get("host"));
        if (isBlank(hostVal) && settings.addMissingHost && !isBlank(uriHost)) {
            hostVal = uriHost.trim();
            apply.put("host", hostVal);
            headers.put("host", List.of(hostVal));
        }

        String xDateVal = first(headers.get("x-date"));
        String dateVal = first(headers.get("date"));
        if (isBlank(xDateVal) && isBlank(dateVal)
                && (settings.addMissingDate || (addDateIfSigning && settings.signDate))) {
            dateVal = RFC1123.format(ZonedDateTime.now(java.time.ZoneOffset.UTC));
            apply.put("date", dateVal);
            headers.put("date", List.of(dateVal));
        }

        // Delegation (OBO) token: always overwrite (not "only if missing" like host/date
        // above) so the Profile's configured value wins over any stale opc-obo-token
        // header already sitting on a Repeater-resent request -- otherwise we could sign
        // over one value while a different, stale value physically goes out on the wire.
        String deleg = nz(delegationToken);
        if (!deleg.isBlank()) {
            apply.put("opc-obo-token", deleg);
            headers.put("opc-obo-token", List.of(deleg));
        }

        String xcsVal = first(headers.get("x-content-sha256"));
        String clVal = first(headers.get("content-length"));
        String ctVal = first(headers.get("content-type"));

        if (considerBody && !objectStoragePut) {
            if (settings.signXContentSha256) {
                if (isBlank(xcsVal)) {
                    if (settings.computeMissingXContentSha256) {
                        xcsVal = OciTokenUtils.base64Sha256(effectiveBodyBytes);
                        apply.put("x-content-sha256", xcsVal);
                        headers.put("x-content-sha256", List.of(xcsVal));
                    } else {
                        throw new IllegalArgumentException("x-content-sha256 is required (missing and auto-compute disabled).");
                    }
                }
            }

            if (settings.signContentLength) {
                if (isBlank(clVal)) {
                    if (settings.computeMissingContentLength) {
                        clVal = String.valueOf(effectiveBodyBytes.length);
                        apply.put("content-length", clVal);
                        headers.put("content-length", List.of(clVal));
                    } else {
                        throw new IllegalArgumentException("content-length is required (missing and auto-compute disabled).");
                    }
                }
            }

            if (settings.signContentType) {
                if (isBlank(ctVal)) {
                    throw new IllegalArgumentException("content-type is required for body signing but is missing.");
                }
            }
        }

        LinkedHashSet<String> headersToSign = new LinkedHashSet<>();
        if (settings.signRequestTarget) headersToSign.add("(request-target)");
        if (settings.signDate) headersToSign.add(isBlank(first(headers.get("x-date"))) ? "date" : "x-date");
        if (settings.signHost) headersToSign.add("host");
        if (!deleg.isBlank()) headersToSign.add("opc-obo-token");

        if (considerBody && !objectStoragePut) {
            if (settings.signXContentSha256) headersToSign.add("x-content-sha256");
            if (settings.signContentType) headersToSign.add("content-type");
            if (settings.signContentLength) headersToSign.add("content-length");
        }

        if (objectStoragePut) {
            if (!isBlank(xcsVal)) headersToSign.add("x-content-sha256");
            if (!isBlank(ctVal)) headersToSign.add("content-type");
            if (!isBlank(clVal)) headersToSign.add("content-length");
        }

        for (String extra : settings.extraHeadersList()) {
            headersToSign.add(extra.toLowerCase(Locale.ROOT));
        }

        if (headersToSign.contains("host") && isBlank(first(headers.get("host")))) {
            throw new IllegalArgumentException("host is selected to be signed but is missing (and auto-add failed/disabled).");
        }
        if (headersToSign.contains("x-date") && isBlank(first(headers.get("x-date")))) {
            throw new IllegalArgumentException("x-date is selected to be signed but is missing.");
        }
        if (headersToSign.contains("date") && isBlank(first(headers.get("date")))) {
            throw new IllegalArgumentException("date is selected to be signed but is missing (and auto-add disabled).");
        }

        List<String> headersToSignList = new ArrayList<>(headersToSign);
        String signingString = buildSigningString(headersToSignList, m, target, headers);

        return new Prepared(m, target, headers, apply, headersToSignList, signingString, considerBody);
    }

    public static String buildSigningString(List<String> headersToSign,
                                            String methodUpper,
                                            String requestTarget,
                                            Map<String, List<String>> headers) {
        // Example output:
        //   (request-target): get /n/
        //   date: Wed, 04 Mar 2026 01:30:11 GMT
        //   host: objectstorage.us-phoenix-1.oraclecloud.com
        String methodLower = methodUpper.toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < headersToSign.size(); i++) {
            String h = headersToSign.get(i);

            if ("(request-target)".equalsIgnoreCase(h)) {
                sb.append("(request-target): ").append(methodLower).append(" ").append(requestTarget);
            } else {
                String key = h.toLowerCase(Locale.ROOT);
                String v = first(headers.get(key));
                if (v == null) v = "";
                sb.append(key).append(": ").append(v);
            }
            if (i < headersToSign.size() - 1) sb.append("\n");
        }
        return sb.toString();
    }

}
