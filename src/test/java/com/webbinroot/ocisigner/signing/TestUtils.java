package com.webbinroot.ocisigner.signing;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

final class TestUtils {
    static final String FIXED_DATE = "Tue, 03 Mar 2026 12:00:00 GMT";
    static final String FIXED_PRIVATE_KEY_PEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCbskjmLTqwrXis\n" +
            "wLt4/a7v7InlFtX4wAYq8AcoiW24XB0m8V/1vQ7+9X6v3uzJlIGLV46gFeWFIa+l\n" +
            "lu2uriHTrRU7ARyPNPFzgLau8HEFuEz4Idvq2RQlh/ba3aEyCGSyefXfenoEb9PA\n" +
            "6aCKBjyrPwJs7//UT0expFckEMDMcNHEzfwGC25iClLvyffbI5Q4ieX2SwureWWa\n" +
            "TVrlim+AG924aG2Gj5HzNc25ktByZbv/nFQtAn+Ktqd1y1uRAt9mcSB1ZmkL5jkX\n" +
            "06TPkhOMTteTDX/gCIiJCHhypTzb8WHtcrBWhPdGlR2leDmN+ed+ZEsQrCb2oROc\n" +
            "71SKCbztAgMBAAECggEAB4viJanujM6zqSfkTk55cq6T1nM/ZsGj6uPcbPYQR93L\n" +
            "Ge6cGJSTy/7JJ6wV7QVSLBdP1emJyOSjl1KT7aIKCLD8dPIuWLCXvWHxONR1nfHb\n" +
            "ZTF678yaweDvsZcJb5vhiZcIuE6+6EUlTdXlDpuTyDcTHoWZcEhxcKZHBPv85EvG\n" +
            "LAQSXA907iWhm2HnKKUJHEz7BVmTvAzgEVpwem0O1SJTrxYaKqt+12D++Js2eyBN\n" +
            "HHEt4/BVbluzgg2kAVuBoYZH3ciknMJZshT+VgsgARscWsqsPf8kIzj/l85oWZrU\n" +
            "w8ksFCBzihaQ4CXjqaDusrLtFwVw+F4jaNMOGtEBUQKBgQDYqVBb3QGrST+Jo2X6\n" +
            "tlqstDsxlYgdQEM2sUwM40/4dsYN+81HAzgBdu+cSL/BwC1+MvNjnkd5mtpziPJR\n" +
            "92MQR5bZdlBRNd/8oZFAA8uXng8uyveZF41F8vPHWVqnP45fGjHuRUAjyknnoomi\n" +
            "WLJJi0OFK9kuu8LhmlaFkB4m5QKBgQC39z671TzHCZh5/rMBfedY9on+iUA+rZH3\n" +
            "xFXRoEQde8NFFeD2f6l8L7mc3IVHfHEzYiy4iWS4RXAj05xOi+w2CKgeIZQv+y4h\n" +
            "/jPaf1ZL4RpZNHq4G1bcsFfCUiYaoHEqWJjlbFXRTm21DBkePQJIG9tw1VkTPl1t\n" +
            "cxshl98VaQKBgBIcJPFoycjteHgixlVshKvG7OO6IgR/6J5bt4WkQnz8QJXOpFv5\n" +
            "Muc8b87abdzeGW9hBuMeyc6qWPQrUEX1rbwgn8VRlGkVXcGaJ6/4IT5tIcvBf2y2\n" +
            "gUKFikbxexhbwaTFZcMK2s+jCwZnmaWOUGjBUUWCYsb7PtDou66yWzLZAoGAQRkt\n" +
            "ytv3SNt9aFYX1ARQlGuRg0/gOw3CpHGGiMp0sBY2kEDgvXmJaReeUAK86wH/MNah\n" +
            "yp9b09VGjHb6TdU3vhssGpV5Uc1Jkt/YS45Z5DoAz+ZBMtsBztBcDbhyIWP7B6gY\n" +
            "Wr8OUyW0rqdcUBX4s7mf2nq0rZmZB/z+cdHDMFkCgYBYTcUgmjppcaKXWHtUJt12\n" +
            "M/UchhiHjlkv+cPV+rmmz/t/5HooBk9yMmNEdc5WkafHG5VokGsBGYwVCWAyrlCp\n" +
            "5e0nLzB1DU8L5ngP4BNJ44F4QAGo7+AT/2opqyBfo9N/o9sZhJarJGUfI+oCPUMt\n" +
            "ja+8W95awLGdvhxxFLGIHA==\n" +
            "-----END PRIVATE KEY-----\n";

    static final String SIG_API_GET =
            "GwxEdwyIXYatRBfWQs1uR6vz4XHBo07uwvg+bi9crBpifyYFsNUX5Am2ExmyppXC0okhp/xywZyCpPqLQU9RWrGI4emigdzFLXcvfHNBOFMzMgnO/msFZiTMPmtfrqt/RQpDZIahKRoRvmLI4JoIKH/QpX1oMO6CY0z7T666yG+3tFtBqqtHJGWHy6g5pnvrThNw0B0UTLLRKjqDot1LUuFUKTy7ZJ6NAcP41YtyZvza1ORMbCP8M7QCeV6MutaPC5PDgJ5cpDQxuoCe+PlG/19nHq+OJmbYjkZAPIFc102gXcjxtma+UTx4lsVfBaTZEelBkKp/7vwmF0llDhGAqw==";
    static final String SIG_API_POST =
            "m5IZSbhukV/LpKxX3J5elXbhVUVfCx60jXoS09xhrwspUp628Q4AE83Jco0MzcPSPyjLg4SxnwR8Hd7t1a5DEj8/Bs5QbTxK2IpoVoNqumBtr3lcfGFXhjzR9NNImEvi2scHyMf0a59MJz+1q9UsEzDDKqWzwnJ3z9u+HrsejGXpUxMzi0QFiBg8L5vU4THxAWfF5rRJ9TRC1Z/ktgrRi25cML/acojWmh1yRqh+xGWkY4hSLxauvxePeQuU/XgtCYcqLtIIxUE9tBeoFd/o6A3NvXFspZd/cs7oZWWaF4SOY8VFBNr/piG++X0Z1xtP7HwvC/AUHLf//ZDRxJ9qmA==";
    static final String SIG_API_EXTRA =
            "ce05ogoU3p6jqZ1ekQMR7iYThOVtHl59MjOkGBJA6NQeA3bf5i1M/Tcujv+HXdQoCjsls6nBpnS6lhKXo+iM0G4UNs4XCgXDUVcG9q+vk/NBNFurfYkB75OitgyrXhJhvvsqikm17NB78LZ9P2T0N3xSgNkehf/8eIvgpS6l1w58MX/pHcZodHll8jPTdWwP12hVwfOvOpv4Lo3OffAF4vQEvyehtEaJuZ8bz2MCTHMVNNCaOZ1eW6EwkRZBySwWVlsGPEi6ofxKbfhqjeDJK1kGMm8p8FLU5nutw+OV7B9Vm9+sWIMrTnFa+SPJL0EwzDEwAeBNndXsLLoqphRiNQ==";
    static final String SIG_API_GET_WITH_BODY =
            "OfbuRLJCilm6V3bZv11MXcp3tTSHye0yPEDVnOykrOP5Ka2Ne44hm8OAOsIkQE3C1r0XJBcMBWGiilf+Pyz1DIrHGK9jhuzTRqAhEiUMH7q5y5ONOTS2djU0Q3XBS+T6My4nAHeOy7wHDgitMCS6tTnYZJObNOdlM17LgOZBZp7OZUkMRaVv2ietjL6bpeoxONMsBNz1MPaeixztT6rNmICBxAuTkgJpO/fXeKP06BVY642dO0BiHg1GD1FuMy2pmWYes5fdXx5ZGShQ4vPe5iWhIqHb7XDHukHxvhdXqTgmwP/R9WwhRzNnNmJZU6sK8kihHsOZLKaW4A1fKM0FhA==";
    static final String SIG_API_DELETE_WITH_BODY =
            "Jh61tG0YKKtko+0qDUVEOKzsvzrdVfLh4r5rQVMpO3vv10w9uR8ZxNorhNN05/1OYmutdEcht/ChCdaV8lvlbNUnZCTlaMY1V0jjn2/Ho5F/9Izb7qVUIz3d9RHoU1PutYGzxcA9jbBJq2EnbBn88gHC/S0sb4P6GbvnZA1Q6jYbUxBPfEeL86/NsIrExKvCpIuaB4Ms69QUrm5lptcP/AY/C82//RikKMPHR0L771///NzASNO3NNw/YPSu5Fo/UdT5cA33as/asPTMAhxbatJB00sJGI+vd7+jt0bCSfPt7TLuP63hAHwaLgILs7uA5mTc1O2k5iPLZsbhZtNUEw==";
    static final String SIG_API_NO_DATE =
            "ZiN013c22bKamIwNNEnWhjrUNDtnMqDDK7MgswLY5BkLIbO/CYpQrDWaoc11MfxN5/SWlt8aWPaTC5XFp5VuShqeYN57Axmpb3htJAIMN6to+ALEIXSF5ZwdGydOjA02gXhC9VnnoIBwmEOktY5hBhfUzq3sn7MVXZz9A8+PjlQbMoIZLJlnYRwV7E9eALk7GtNigx7hM16ydcf/+82kCgWvSXXg6sADwyvYEEPFpSVO8BtG3OiYGolTNJ0++HCcn86gFSTllW0ohMA/YMsGLAfmDdZ+lxs6l+jyhqO0N2XhvjR683ipIuOzhA5ty9Kg89NQig1sX7LRgiqkHIdfDw==";
    static final String SIG_API_OBJECTSTORAGE_PUT =
            "mXAaJzIN6EzI+wo/4cZQh3yz2oPvr3bq7dIpXplt+/FUZFpBuHLy60lHDhV29UF+dr18Oji5cwJgq+bKApWmTeIHpSCqXdX/En1EworgT0utxWi0IT6e5b0Lb+kP+CcesxeeY7TgwwnV9GFG9kU5k3ym7oYEuYRvWBikrDaVFX38aqiBtaNYsrb/O56JyGxtcPicyLnA1r9V/IpYzO3yQXi6GEYzSoiiXGxZE+H/iEK9ZPjOw2x4Xircg2e/z6REM3tH13XMMhSrpn16gIhlOvvOvi0i8JKDtVJ9+MTiVeO1gHA5Oah+nq4Vs4Ab2OqjGWr7nZpFfeDaY9RyUoeqAw==";
    static final String SIG_API_OBJECTSTORAGE_PUT_WITH_BODY_HEADERS =
            "JVSwaDYignl8spYguIL8hI0TkqLx+Sj/OzkkxHmUKH+ogmDLioeZsvg7sX1vcBaBpzAN9lizQo3Zh+pX9WRYz7dQGos+xKNdIgX0NbqdnLsSDxQ9lkkrtX1EGA10A0XMrvY+vmEPvaMJkSBnsEg6vlZEdU4zQ2GLASxgp48Fj7B9mb5qyjNLKUQq6em8Q2RumT53Dib0+vMfVjjmS1FkQ5o8bY333AGia/Vevc+sLfH0drYkAKU8+6GgGeizGFXSgfg7bp6dNyxi/iJgwzoyUHWPMxngQnuWMqN8zheLwfaxsjRyVMoLFeuuyp3TYgBiXF9PtGTXn+LPETVouaEH3A==";
    static final String SIG_SESSION_IDENTITY =
            "R4xTL7yi9SyJOJPHJcULy5PNpFTckyLzPfqihbigTYzk6yOKGbu1Mrh+YfbZIq2R51U7elJp1aVskPRoHDU3SaoKIUFIDZeGIsodhZECWgGFU38ORKtXEr8xCDp+SIbbgU68RDV2FGhBiplasJBmqGqLsXtkNK/WBa5nv/DXmPL4Lr8zYpjUxDdXLJp9uXcKcVXM1LfQDmDZ/0hSw5+1B2S7c38umaQz7yMa6Hj4woG4NOKsNmaxBb7q3B4YCM86yxtWHVjVksKkh7wMWX0r1r9/FDnAbEDPtfjxrTQfiFrFJsU35EccbZJztAvLLRYn4g7qdqVcdPRTlBWU8Qe0bQ==";
    static final String SIG_SESSION_OBJECTSTORAGE = SIG_API_GET;
    static final String SIG_HMAC_GET =
            "Z6N0307C1IDNgLzvXXPuexut2tawX8reRXAZ4e6S2ZA=";

    private static final PrivateKey FIXED_PRIVATE_KEY = loadFixedPrivateKey();
    private static final PublicKey FIXED_PUBLIC_KEY = derivePublicKey(FIXED_PRIVATE_KEY);

    private TestUtils() {}

    static KeyPair fixedKeyPair() {
        return new KeyPair(FIXED_PUBLIC_KEY, FIXED_PRIVATE_KEY);
    }


    private static PrivateKey loadFixedPrivateKey() {
        try {
            return loadPkcs8PrivateKey(FIXED_PRIVATE_KEY_PEM);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load fixed private key", e);
        }
    }

    static String base64Sha256(byte[] data) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(data));
    }

    static void verifySignature(String authorizationHeader,
                                String signingString,
                                PublicKey publicKey,
                                String expectedAlg) throws Exception {
        String alg = extractParam(authorizationHeader, "algorithm");
        String sigB64 = extractParam(authorizationHeader, "signature");

        assertEquals(expectedAlg, alg);
        assertNotNull(sigB64);

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(publicKey);
        s.update(signingString.getBytes(StandardCharsets.UTF_8));
        assertTrue(s.verify(Base64.getDecoder().decode(sigB64)));
    }

    static String expectedManualAuthorizationHeaderWithSig(String keyId,
                                                           String headersList,
                                                           String algorithm,
                                                           String signature) {
        return "Signature " +
                "version=\"1\"," +
                "keyId=\"" + keyId + "\"," +
                "algorithm=\"" + algorithm + "\"," +
                "headers=\"" + headersList + "\"," +
                "signature=\"" + signature + "\"";
    }

    static String expectedSessionAuthorizationHeaderWithSig(String keyId,
                                                            String headersList,
                                                            String algorithm,
                                                            String signature) {
        return expectedManualAuthorizationHeaderWithSig(keyId, headersList, algorithm, signature);
    }

    static String extractParam(String header, String name) {
        String needle = name + "=\"";
        int idx = header.indexOf(needle);
        if (idx < 0) return null;
        int start = idx + needle.length();
        int end = header.indexOf('"', start);
        if (end < 0) return null;
        return header.substring(start, end);
    }

    static String jwtWithExp(long exp) {
        String header = "{\"alg\":\"none\"}";
        String pad = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        String payload = "{\"exp\":" + exp + ",\"pad\":\"" + pad + "\"}";
        String h = base64Url(header.getBytes(StandardCharsets.UTF_8));
        String p = base64Url(payload.getBytes(StandardCharsets.UTF_8));
        return h + "." + p + ".sig";
    }

    static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    static Map<String, List<String>> baseHeaders(String host) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("host", List.of(host));
        headers.put("date", List.of(FIXED_DATE));
        return headers;
    }

    private static PrivateKey loadPkcs8PrivateKey(String pem) throws Exception {
        String cleaned = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(cleaned);
        return KeyFactory.getInstance("RSA").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
    }

    private static PublicKey derivePublicKey(PrivateKey pk) {
        if (pk instanceof RSAPrivateCrtKey crt) {
            try {
                RSAPublicKeySpec spec = new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            } catch (Exception e) {
                throw new IllegalStateException("Failed deriving RSA public key", e);
            }
        }
        throw new IllegalStateException("Private key is not RSA CRT");
    }
}
