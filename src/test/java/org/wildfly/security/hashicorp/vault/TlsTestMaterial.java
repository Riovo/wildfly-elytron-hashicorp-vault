/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.ExtendedKeyUsageExtension;
import org.wildfly.security.x500.cert.KeyUsage;
import org.wildfly.security.x500.cert.KeyUsageExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.SubjectAlternativeNamesExtension;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

/**
 * One CA and one CA-signed identity, represented consistently in PEM and JKS.
 * The caller owns the directory and must remove it after use, including failures.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public record TlsTestMaterial(Path root, Path certFile, Path keyFile, Path trustFile,
        Path keyStoreFile, Path trustStoreFile) {

    public static final String STORE_PASSWORD = "secret";

    public static Path temporaryDirectory(String prefix) throws IOException {
        Path base = Path.of("target", "tls-fixtures").toAbsolutePath();
        return Files.createTempDirectory(Files.createDirectories(base), prefix);
    }

    public static TlsTestMaterial generate(Path root, String host, boolean client) throws Exception {
        Files.createDirectories(root);
        ZonedDateTime now = ZonedDateTime.now();
        SelfSignedX509CertificateAndSigningKey ca = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal("CN=Vault Test CA"))
                .setKeyAlgorithmName("RSA").setKeySize(2048)
                .setSignatureAlgorithmName("SHA256withRSA")
                .setNotValidBefore(now.minusDays(1)).setNotValidAfter(now.plusDays(30))
                .addExtension(new BasicConstraintsExtension(true, true, 0))
                .addExtension(new KeyUsageExtension(KeyUsage.keyCertSign, KeyUsage.cRLSign))
                .build();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        X509CertificateBuilder builder = new X509CertificateBuilder()
                .setIssuerDn(ca.getSelfSignedCertificate().getSubjectX500Principal())
                .setSubjectDn(new X500Principal(client ? "CN=Vault Test Client" : "CN=Vault Test Server"))
                .setSerialNumber(new BigInteger(159, new SecureRandom()).add(BigInteger.ONE))
                .setNotValidBefore(now.minusDays(1)).setNotValidAfter(now.plusDays(30))
                .setSigningKey(ca.getSigningKey()).setPublicKey(keys.getPublic())
                .setSignatureAlgorithmName("SHA256withRSA")
                .addExtension(new BasicConstraintsExtension(true, false, -1))
                .addExtension(new KeyUsageExtension(KeyUsage.digitalSignature, KeyUsage.keyEncipherment))
                .addExtension(new ExtendedKeyUsageExtension(false,
                        List.of(client ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1")));
        if (!client) {
            GeneralName hostName = host.contains(":") || host.matches("[0-9.]+")
                    ? new GeneralName.IPAddress(host) : new GeneralName.DNSName(host);
            builder.addExtension(new SubjectAlternativeNamesExtension(false, List.of(hostName,
                    new GeneralName.DNSName("localhost"), new GeneralName.IPAddress("127.0.0.1"))));
        }
        X509Certificate leaf = builder.build();
        TlsTestMaterial material = new TlsTestMaterial(root, root.resolve("identity.crt"),
                root.resolve("identity.key"), root.resolve("ca.crt"),
                root.resolve("identity.jks"), root.resolve("trust.jks"));
        Files.writeString(material.certFile(), pem("CERTIFICATE", leaf.getEncoded())
                + pem("CERTIFICATE", ca.getSelfSignedCertificate().getEncoded()));
        Files.writeString(material.keyFile(), pem("PRIVATE KEY", keys.getPrivate().getEncoded()));
        Files.writeString(material.trustFile(), pem("CERTIFICATE", ca.getSelfSignedCertificate().getEncoded()));

        char[] password = STORE_PASSWORD.toCharArray();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, password);
        keyStore.setKeyEntry("identity", keys.getPrivate(), password,
                new X509Certificate[] { leaf, ca.getSelfSignedCertificate() });
        save(keyStore, material.keyStoreFile(), password);
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, password);
        trustStore.setCertificateEntry("ca", ca.getSelfSignedCertificate());
        save(trustStore, material.trustStoreFile(), password);
        return material;
    }

    private static void save(KeyStore store, Path file, char[] password) throws Exception {
        try (OutputStream out = Files.newOutputStream(file)) {
            store.store(out, password);
        }
    }

    private static String pem(String type, byte[] encoded) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(encoded)
                + "\n-----END " + type + "-----\n";
    }
}
