/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class SensitiveValueHasher {

    private static final byte[] HMAC_KEY;
    static {
        HMAC_KEY = new byte[32];
        new SecureRandom().nextBytes(HMAC_KEY);
    }

    private SensitiveValueHasher() {}

    static String hashForLog(String value) {
        if (value == null) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(HMAC_KEY, "HmacSHA256"));
            byte[] digest = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder("hmac:");
            for (int i = 0; i < 4; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (Exception e) {
            return "<hash-unavailable>";
        }
    }

    static void traceLog(String format, String sensitiveFirstParam, Object... remainingParams) {
        if (!ROOT_LOGGER.isTraceEnabled()) {
            return;
        }
        String hashed = hashForLog(sensitiveFirstParam);
        Object[] allArgs = new Object[remainingParams.length + 1];
        allArgs[0] = hashed;
        System.arraycopy(remainingParams, 0, allArgs, 1, remainingParams.length);
        ROOT_LOGGER.tracef(format, allArgs);
    }
}
