/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault.auth;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.testcontainers.utility.MountableFile;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.hashicorp.vault.TlsTestMaterial;

/**
 * Utility which will configure a vault container for TLS certificate authentication method.
 */
public class TlsCertAuthConfig implements VaultContainerAuthConfig {

    private final Path certsRootInContainer = Path.of("/vault/auth-certs");

    private final TlsTestMaterial pemCertificateFiles;
    private final List<String> policies;

    private TlsCertAuthConfig(Builder builder) {
        this.pemCertificateFiles = builder.pemCertificateFiles;
        this.policies = builder.policies.isEmpty() ? Collections.singletonList("root") : builder.policies;
    }

    @Override
    public void configure(VaultContainer<?> vaultContainer) {
        if (vaultContainer.isRunning()) {
            throw new IllegalStateException();
        }

        final MountableFile certRootPath = MountableFile.forHostPath(pemCertificateFiles.root(), 0777);

        vaultContainer.withCopyFileToContainer(certRootPath, certsRootInContainer.toAbsolutePath().toString());
        vaultContainer.withInitCommand("auth enable cert");
        vaultContainer.withInitCommand(String.format("write auth/cert/certs/test-root \\\n" +
                "    display_name=\"root-cert-test\" \\\n" +
                "    policies=\"%s\" \\\n" +
                "    certificate=@%s", String.join(",", policies),
                certsRootInContainer.resolve(pemCertificateFiles.certFile().getFileName()).toAbsolutePath()));
    }

    public static final class Builder {

        private final TlsTestMaterial pemCertificateFiles;

        private final List<String> policies = new LinkedList<>();

        /**
         * Create new builder instance
         * @param pemCertificateFiles certificates which will be used to configure TLS authentication. The trust file/ca
         *                            file will be used to configure the auth path.
         */
        public Builder(TlsTestMaterial pemCertificateFiles) {
            this.pemCertificateFiles = pemCertificateFiles;
        }

        /**
         * Configure policies for given login method. By default, dev mode for the Vault is assumed and root policy is
         * used if none is configured
         * @param policies list of policies. E.g. root, default
         * @return instance of this builder
         */
        public Builder policies(String... policies) {
            this.policies.addAll(Arrays.asList(policies));
            return this;
        }

        public TlsCertAuthConfig build() {
            return new TlsCertAuthConfig(this);
        }

    }
}
