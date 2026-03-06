package com.webbinroot.ocisigner.signing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OciSigningUtilsTest {

    @Test
    void objectStorage_putObject_and_uploadPart_routes_are_detected_as_special_put_only() {
        String host = "objectstorage.us-phoenix-1.oraclecloud.com";

        assertTrue(OciSigningUtils.isObjectStoragePutSpecial(
                "PUT",
                host,
                "/n/ns/b/bkt/o/object-name"
        ));

        assertTrue(OciSigningUtils.isObjectStoragePutSpecial(
                "PUT",
                host,
                "/n/ns/b/bkt/u/upload-id/id/1"
        ));

        assertFalse(OciSigningUtils.isObjectStoragePutSpecial(
                "POST",
                host,
                "/n/ns/b/bkt/o/object-name"
        ));

        assertFalse(OciSigningUtils.isObjectStoragePutSpecial(
                "PUT",
                host,
                "/n/ns/b/bkt/o/"
        ));

        assertFalse(OciSigningUtils.isObjectStoragePutSpecial(
                "PUT",
                "identity.us-phoenix-1.oci.oraclecloud.com",
                "/n/ns/b/bkt/o/object-name"
        ));
    }
}
