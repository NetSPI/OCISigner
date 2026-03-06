package com.webbinroot.ocisigner.keys;

import com.webbinroot.ocisigner.util.OciDebug;
import com.oracle.bmc.auth.X509CertificateSupplier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;

/**
 * X.509 helpers for Instance/Resource Principals when certs/keys are provided manually.
 *
 * Accepts either:
 *  - file path (preferred), or
 *  - inline PEM content.
 */
public final class OciX509Suppliers {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private OciX509Suppliers() {}

    /**
     * Build a leaf certificate supplier from PEM strings or file paths.
     *
     * Example input:
     *  - certSource="/home/kali/leaf.pem"
     *  - keySource="/home/kali/key.pem"
     * Example output:
     *  - X509CertificateSupplier with certificate + private key
     */
    public static X509CertificateSupplier leafSupplier(String certSource, String keySource, String keyPassphrase) {
        OciDebug.debug("[OCI Signer][X509] Loading leaf cert: " + describeSource(certSource));
        OciDebug.debug("[OCI Signer][X509] Loading leaf key: " + describeSource(keySource)
                + " | passphraseLen=" + (keyPassphrase == null ? 0 : keyPassphrase.length()));
        X509Certificate cert = loadCertificate(certSource);
        RSAPrivateKey key = loadPrivateKey(keySource, keyPassphrase);
        OciDebug.debug("[OCI Signer][X509] Leaf cert subject: " + safeSubject(cert)
                + " | keyAlg=" + (key == null ? "null" : key.getAlgorithm())
                + " | keyBits=" + (key == null ? 0 : key.getModulus().bitLength()));
        return new StaticX509Supplier(cert, key);
    }

    /**
     * Parse intermediate certificates from a newline/semicolon/comma-separated list.
     *
     * Example input:
     *  - "/path/intermediate.pem"
     *  - "/path/intermediate1.pem;/path/intermediate2.pem"
     * Example output:
     *  - List of X509CertificateSupplier (each contains a cert only)
     */
    public static List<X509CertificateSupplier> intermediateSuppliers(String sourcesMultiline) {
        List<X509CertificateSupplier> out = new ArrayList<>();
        if (sourcesMultiline == null || sourcesMultiline.trim().isEmpty()) return out;

        String[] parts = sourcesMultiline.split("[\\r\\n;,]+");
        OciDebug.debug("[OCI Signer][X509] Intermediate cert entries: " + parts.length);
        for (String ln : parts) {
            if (ln == null) continue;
            String v = ln.trim();
            if (v.isEmpty()) continue;

            OciDebug.debug("[OCI Signer][X509] Loading intermediate: " + describeSource(v));
            List<X509Certificate> certs = loadCertificates(v);
            for (X509Certificate c : certs) {
                out.add(new StaticX509Supplier(c, null));
            }
        }
        OciDebug.debug("[OCI Signer][X509] Total intermediate certs parsed: " + out.size());
        return out;
    }

    private static X509Certificate loadCertificate(String source) {
        List<X509Certificate> certs = loadCertificates(source);
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("X.509 certificate not found.");
        }
        return certs.get(0);
    }

    private static List<X509Certificate> loadCertificates(String source) {
        String pem = readSource(source);
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("X.509 certificate source is empty.");
        }

        List<X509Certificate> out = new ArrayList<>();
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj;
            while ((obj = parser.readObject()) != null) {
                if (obj instanceof X509CertificateHolder holder) {
                    out.add(new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                            .setProvider("BC")
                            .getCertificate(holder));
                }
            }
            OciDebug.debug("[OCI Signer][X509] Parsed certificate count: " + out.size());
        } catch (IOException | CertificateException e) {
            OciDebug.logStack("[OCI Signer][X509] Failed parsing X.509 certificate", e);
            throw new IllegalArgumentException("Failed parsing X.509 certificate: " + e.getMessage(), e);
        }

        return out;
    }

    private static RSAPrivateKey loadPrivateKey(String source, String passphrase) {
        String pem = readSource(source);
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("Private key source is empty.");
        }

        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj == null) {
                throw new IllegalArgumentException("Private key not found.");
            }

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (obj instanceof PEMEncryptedKeyPair enc) {
                if (passphrase == null || passphrase.isEmpty()) {
                    throw new IllegalArgumentException("Encrypted private key requires a passphrase.");
                }
                try {
                    PEMKeyPair kp = enc.decryptKeyPair(new JcePEMDecryptorProviderBuilder()
                            .build(passphrase.toCharArray()));
                    PrivateKey key = converter.getKeyPair(kp).getPrivate();
                    return (RSAPrivateKey) key;
                } catch (Exception e) {
                    throw new IllegalArgumentException("Failed decrypting private key: " + e.getMessage(), e);
                }
            }

            if (obj instanceof PEMKeyPair kp) {
                OciDebug.debug("[OCI Signer][X509] Private key type: PEMKeyPair");
                PrivateKey key = converter.getKeyPair(kp).getPrivate();
                return (RSAPrivateKey) key;
            }

            if (obj instanceof PrivateKeyInfo info) {
                OciDebug.debug("[OCI Signer][X509] Private key type: PKCS8 PrivateKeyInfo");
                PrivateKey key = converter.getPrivateKey(info);
                return (RSAPrivateKey) key;
            }

            if (obj instanceof PKCS8EncryptedPrivateKeyInfo enc) {
                OciDebug.debug("[OCI Signer][X509] Private key type: Encrypted PKCS8");
                if (passphrase == null || passphrase.isEmpty()) {
                    throw new IllegalArgumentException("Encrypted private key requires a passphrase.");
                }
                try {
                    PrivateKeyInfo info = enc.decryptPrivateKeyInfo(
                            new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase.toCharArray())
                    );
                    PrivateKey key = converter.getPrivateKey(info);
                    return (RSAPrivateKey) key;
                } catch (OperatorCreationException | org.bouncycastle.pkcs.PKCSException e) {
                    OciDebug.logStack("[OCI Signer][X509] Failed decrypting private key", e);
                    throw new IllegalArgumentException("Failed decrypting private key: " + e.getMessage(), e);
                }
            }

            throw new IllegalArgumentException("Unsupported private key format.");

        } catch (IOException e) {
            OciDebug.logStack("[OCI Signer][X509] Failed parsing private key", e);
            throw new IllegalArgumentException("Failed parsing private key: " + e.getMessage(), e);
        }
    }

    /**
     * Load an RSA private key from a PEM source (file path or inline PEM).
     * This reuses the same parsing logic as the X.509 suppliers.
     *
     * Example input:
     *  - "/home/kali/key.pem"
     * Example output:
     *  - RSAPrivateKey instance
     */
    public static RSAPrivateKey loadRsaPrivateKey(String source, String passphrase) {
        return loadPrivateKey(source, passphrase);
    }

    private static String readSource(String source) {
        if (source == null) return "";
        String s = source.trim();
        if (s.isEmpty()) return "";

        // If it looks like PEM content, use directly.
        if (s.contains("-----BEGIN")) {
            OciDebug.debug("[OCI Signer][X509] Source is inline PEM (len=" + s.length() + ")");
            return s;
        }

        // Otherwise treat as a file path.
        try {
            Path p = Path.of(s);
            if (!Files.isRegularFile(p)) {
                OciDebug.debug("[OCI Signer][X509] Source not a file, treating as raw text (len=" + s.length() + ")");
                return s; // allow raw text if file does not exist
            }
            long size = Files.size(p);
            OciDebug.debug("[OCI Signer][X509] Reading file: " + p + " (bytes=" + size + ")");
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (Exception e) {
            OciDebug.logStack("[OCI Signer][X509] Failed reading source; treating as raw text", e);
            // Fall back to treating it as raw text if path is invalid.
            return s;
        }
    }

    private static String describeSource(String source) {
        if (source == null) return "(null)";
        String s = source.trim();
        if (s.isEmpty()) return "(empty)";
        if (s.contains("-----BEGIN")) return "inline PEM (len=" + s.length() + ")";
        try {
            Path p = Path.of(s);
            if (Files.isRegularFile(p)) {
                long size = Files.size(p);
                return "file:" + p + " (bytes=" + size + ")";
            }
        } catch (Exception ignored) {}
        return "raw text (len=" + s.length() + ")";
    }

    private static String safeSubject(X509Certificate cert) {
        try {
            if (cert == null) return "null";
            return cert.getSubjectX500Principal().getName();
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static final class StaticX509Supplier implements X509CertificateSupplier {
        private final X509Certificate cert;
        private final RSAPrivateKey key;

        StaticX509Supplier(X509Certificate cert, RSAPrivateKey key) {
            this.cert = cert;
            this.key = key;
        }

        @Override
        @Deprecated
        @SuppressWarnings("deprecation")
        public X509Certificate getCertificate() {
            return cert;
        }

        @Override
        @Deprecated
        @SuppressWarnings("deprecation")
        public RSAPrivateKey getPrivateKey() {
            return key;
        }

        @Override
        public CertificateAndPrivateKeyPair getCertificateAndKeyPair() {
            return new CertificateAndPrivateKeyPair(cert, key);
        }
    }
}
