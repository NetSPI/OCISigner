package com.webbinroot.ocisigner.util; // Package namespace for utility helpers.

import com.fasterxml.jackson.databind.JsonNode; // Jackson JSON node type for parsing token JSON.
import com.fasterxml.jackson.databind.ObjectMapper; // Jackson object mapper used to parse JSON.

import java.io.IOException; // Exception for file IO in ensureTokenFile.
import java.nio.charset.StandardCharsets; // Charset for reading/writing token files.
import java.nio.file.Files; // File IO helper.
import java.nio.file.Path; // Path type for filesystem access.

/**
 * Shared helpers for token handling (JWT parsing, file resolution, etc.).
 */
public final class OciTokenUtils { // Utility class (static-only).

    private static final ObjectMapper MAPPER = new ObjectMapper(); // JSON parser reused across calls.

    private OciTokenUtils() {} // Prevent instantiation.

    /**
     * Resolve a token string from either:
     * - a raw JWT
     * - a file path containing the token
     * - a JSON blob containing {"token":"..."}
     *
     * Example inputs/outputs:
     *  - "/home/kali/.oci/sessions/TEST/token" -> "<JWT from file>"
     *  - "eyJhbGciOi..." -> "eyJhbGciOi..."
     *  - "{\"token\":\"eyJhbGciOi...\"}" -> "eyJhbGciOi..."
     */
    public static String resolveTokenValue(String tokenOrPath) { // Main resolver used by signing flows.
        String raw = (tokenOrPath == null) ? "" : tokenOrPath.trim(); // Normalize input (null-safe).
        if (raw.isBlank()) return ""; // Empty input -> empty output.

        String expanded = expandHome(raw); // Expand "~/" prefix if present.
        String content = raw; // Default to raw input string.
        try { // Try reading as a file path.
            Path p = Path.of(expanded); // Convert to Path.
            if (Files.exists(p) && Files.isRegularFile(p)) { // If file exists,
                content = Files.readString(p, StandardCharsets.UTF_8); // read file contents.
            }
        } catch (Exception ignored) {} // Ignore invalid paths or IO errors.

        String trimmed = content.trim(); // Trim whitespace from content.
        if (trimmed.startsWith("{")) { // If it looks like JSON,
            try { // parse and extract "token" field.
                JsonNode node = MAPPER.readTree(trimmed); // Parse JSON.
                JsonNode token = node.get("token"); // Get "token" field.
                if (token != null && token.isTextual()) { // If it's a string,
                    return token.asText().trim(); // return its trimmed value.
                }
            } catch (Exception ignored) {} // Ignore JSON parse failures.
        }

        return trimmed; // Otherwise, return the trimmed content as-is.
    }

    /**
     * Extract a JWT numeric claim (e.g., exp/iat) as epoch seconds.
     *
     * Example input:
     *  - token="eyJhbGciOi..." field="exp"
     * Example output:
     *  - 1772492918 (epoch seconds) or -1 if missing/invalid
     */
    public static long extractJwtTime(String token, String field) { // Generic claim extractor.
        try { // Protect against malformed tokens.
            if (token == null) return -1; // Null token -> invalid.
            String[] parts = token.split("\\."); // JWT is header.payload.signature.
            if (parts.length < 2) return -1; // Need at least header+payload.
            byte[] payload = java.util.Base64.getUrlDecoder().decode(parts[1]); // Decode payload.
            JsonNode node = MAPPER.readTree(payload); // Parse payload JSON.
            JsonNode v = node.get(field); // Read target claim.
            if (v != null && v.isNumber()) return v.asLong(); // Return if numeric.
        } catch (Exception ignored) {} // Any error -> fall through.
        return -1; // Invalid or missing claim.
    }

    public static long extractJwtExp(String token) { // Convenience for exp claim.
        // Example: token -> 1772492918
        return extractJwtTime(token, "exp"); // Delegate to generic extractor.
    }

    public static long extractJwtIat(String token) { // Convenience for iat claim.
        // Example: token -> 1772491200
        return extractJwtTime(token, "iat"); // Delegate to generic extractor.
    }

    /**
     * Ensure the token input points to an existing file path.
     * This method no longer writes temp files (in-memory only policy).
     *
     * Example input:
     *  - "/home/kali/.oci/sessions/TEST/token" -> "/home/kali/.oci/sessions/TEST/token"
     * Example error:
     *  - "eyJhbGciOi..." -> IllegalArgumentException (raw token not allowed here)
     */
    public static String ensureTokenFile(String tokenOrPath) throws IOException { // Validates file path only.
        String raw = (tokenOrPath == null) ? "" : tokenOrPath.trim(); // Normalize input.
        if (raw.isBlank()) throw new IllegalArgumentException("Session token is empty."); // Validate.

        String expanded = expandHome(raw); // Expand ~ for file path.
        Path p = Path.of(expanded); // Build Path.
        if (Files.exists(p)) return p.toAbsolutePath().toString(); // If file exists, return path.

        throw new IllegalArgumentException(
                "Session token must be an existing file path (raw token not allowed in this mode)."
        );
    }

    public static String expandHome(String path) { // Expand "~/" prefix.
        // Example: "~/.oci/config" -> "/home/kali/.oci/config"
        if (path == null) return ""; // Null -> empty.
        String p = path.trim(); // Trim input.
        if (p.startsWith("~" + System.getProperty("file.separator"))) { // If starts with "~/"
            String home = System.getProperty("user.home"); // Get home directory.
            if (home != null && !home.isBlank()) { // If valid,
                return home + p.substring(1); // Replace leading ~ with home.
            }
        }
        return p; // Return unchanged if not expandable.
    }

}
