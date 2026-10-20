/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault._private;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility for hashing sensitive values before logging.
 * Produces a short, non-reversible fingerprint so support engineers can
 * tell whether the same value is being reused across log lines without
 * exposing the plaintext.
 */
public final class SensitiveValueHasher {

    private SensitiveValueHasher() {}

    /**
     * Hash a sensitive value for safe inclusion in log messages.
     *
     * @param value the sensitive value (token, password, etc.)
     * @return {@code "sha256:XXXXXXXX"} (first 8 hex chars of SHA-256), or {@code "<null>"} if value is null
     */
    public static String hashForLog(String value) {
        if (value == null) {
            return "<null>";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder("sha256:");
            for (int i = 0; i < 4; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return "<hash-unavailable>";
        }
    }
}
