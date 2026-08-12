package com.webbinroot.ocisigner.signing;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.anyString;

/**
 * Builds a mocked Montoya HttpRequest from raw HTTP text, for tests that need to call
 * OciRequestSigner.sign() (which takes a real HttpRequest, not a plain header map).
 *
 * Montoya's own HttpRequest.httpRequest(...)/HttpService.httpService(...) static
 * factories throw NullPointerException outside a live Burp instance (they resolve an
 * internal ObjectFactoryLocator that only Burp itself wires up), so building a real one
 * isn't an option here. withUpdatedHeader/withAddedHeader/withRemovedHeader are Montoya's
 * fluent "return a new immutable copy" methods; each is wired to build and return a
 * freshly mocked HttpRequest reflecting the change, so chained mutations behave like the
 * real (immutable) type instead of a stateful mock.
 */
final class MontoyaFakes {

    private MontoyaFakes() {}

    static HttpRequest fakeHttpRequest(String rawHttpText) {
        String[] lines = rawHttpText.split("\r\n", -1);
        String[] requestLine = lines[0].split(" ");
        String method = requestLine[0];
        String path = requestLine[1];

        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        int i = 1;
        for (; i < lines.length; i++) {
            if (lines[i].isEmpty()) {
                i++;
                break;
            }
            int idx = lines[i].indexOf(':');
            headers.put(lines[i].substring(0, idx).trim(), lines[i].substring(idx + 1).trim());
        }

        String bodyText = String.join("\r\n", Arrays.asList(lines).subList(i, lines.length));
        byte[] body = bodyText.isEmpty() ? null : bodyText.getBytes(StandardCharsets.UTF_8);

        return build(method, path, headers, body);
    }

    private static HttpRequest build(String method, String path, LinkedHashMap<String, String> headers, byte[] body) {
        HttpRequest req = mock(HttpRequest.class);

        List<HttpHeader> headerList = toHeaderList(headers);

        when(req.method()).thenReturn(method);
        when(req.path()).thenReturn(path);
        when(req.headers()).thenReturn(headerList);
        when(req.headerValue(anyString())).thenAnswer(inv -> lookup(headers, inv.getArgument(0)));
        when(req.hasHeader(anyString())).thenAnswer(inv -> lookup(headers, inv.getArgument(0)) != null);

        if (body != null) {
            ByteArray ba = mock(ByteArray.class);
            when(ba.getBytes()).thenReturn(body);
            when(req.body()).thenReturn(ba);
        }

        when(req.withUpdatedHeader(anyString(), anyString())).thenAnswer(inv -> {
            LinkedHashMap<String, String> next = new LinkedHashMap<>(headers);
            putCaseInsensitive(next, inv.getArgument(0), inv.getArgument(1));
            return build(method, path, next, body);
        });
        when(req.withAddedHeader(anyString(), anyString())).thenAnswer(inv -> {
            LinkedHashMap<String, String> next = new LinkedHashMap<>(headers);
            putCaseInsensitive(next, inv.getArgument(0), inv.getArgument(1));
            return build(method, path, next, body);
        });
        when(req.withRemovedHeader(anyString())).thenAnswer(inv -> {
            LinkedHashMap<String, String> next = new LinkedHashMap<>(headers);
            removeCaseInsensitive(next, inv.getArgument(0));
            return build(method, path, next, body);
        });

        return req;
    }

    private static List<HttpHeader> toHeaderList(Map<String, String> headers) {
        List<HttpHeader> list = new ArrayList<>();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            HttpHeader h = mock(HttpHeader.class);
            when(h.name()).thenReturn(e.getKey());
            when(h.value()).thenReturn(e.getValue());
            list.add(h);
        }
        return list;
    }

    private static String lookup(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }

    private static void putCaseInsensitive(LinkedHashMap<String, String> headers, String name, String value) {
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                headers.put(key, value);
                return;
            }
        }
        headers.put(name, value);
    }

    private static void removeCaseInsensitive(LinkedHashMap<String, String> headers, String name) {
        headers.keySet().removeIf(key -> key.equalsIgnoreCase(name));
    }
}
