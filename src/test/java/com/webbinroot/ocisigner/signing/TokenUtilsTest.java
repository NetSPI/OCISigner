package com.webbinroot.ocisigner.signing;

import com.webbinroot.ocisigner.util.OciTokenUtils;
import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.*;

class TokenUtilsTest {

    // ResolveTokenValue reads json token
    @Test
    void resolveTokenValue_reads_json_token() throws Exception {
        String json = "{\"token\":\"abc.def.ghi\"}";
        String resolved = OciTokenUtils.resolveTokenValue(json);
        assertEquals("abc.def.ghi", resolved);
    }

    // EnsureTokenFile rejects raw token (no disk writes policy)
    @Test
    void ensureTokenFile_rejects_raw_token() {
        String token = TestUtils.jwtWithExp((System.currentTimeMillis() / 1000) + 3600);
        assertThrows(IllegalArgumentException.class, () -> OciTokenUtils.ensureTokenFile(token));
    }

    // ExtractJwtExp parses exp
    @Test
    void extractJwtExp_parses_exp() {
        long exp = (System.currentTimeMillis() / 1000) + 3600;
        String token = TestUtils.jwtWithExp(exp);
        assertEquals(exp, OciTokenUtils.extractJwtExp(token));
        assertEquals(-1, OciTokenUtils.extractJwtIat(token));
    }
}
