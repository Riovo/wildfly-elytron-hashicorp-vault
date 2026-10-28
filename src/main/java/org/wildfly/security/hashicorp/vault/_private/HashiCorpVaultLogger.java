/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.hashicorp.vault._private;

import static org.jboss.logging.Logger.Level.DEBUG;
import static org.jboss.logging.Logger.Level.ERROR;
import static org.jboss.logging.Logger.Level.TRACE;
import static org.jboss.logging.Logger.Level.WARN;

import java.io.IOException;
import java.lang.invoke.MethodHandles;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;

/**
 * Log messages and typed exceptions for the Elytron HashiCorp Vault integration.
 */
@MessageLogger(projectCode = "ELYHCVT", length = 4)
public interface HashiCorpVaultLogger extends BasicLogger {

    HashiCorpVaultLogger ROOT_LOGGER = Logger.getMessageLogger(MethodHandles.lookup(), HashiCorpVaultLogger.class,
            "org.wildfly.security.hashicorp.vault");

    @Message(id = 1, value = "Attributes cannot be null")
    CredentialStoreException attributesCannotBeNull();

    @Message(id = 2, value = "host-address attribute is required")
    CredentialStoreException hostAddressRequired();

    @Message(id = 3, value = "Vault token is required")
    CredentialStoreException vaultTokenRequired();

    @Message(id = 4, value = "Failed to load KeyStore from path: %s")
    CredentialStoreException failedToLoadKeyStore(String detail, @Cause Exception e);

    @Message(id = 5, value = "Failed to load TrustStore from path: %s")
    CredentialStoreException failedToLoadTrustStore(String detail, @Cause Exception e);

    @Message(id = 6, value = "Failed to initialize vault credential store")
    CredentialStoreException failedToInitializeVaultCredentialStore(@Cause IOException e);

    @Message(id = 7, value = "Failed to configure vault connection")
    CredentialStoreException failedToConfigureVaultConnection(@Cause Exception e);

    @Message(id = 8, value = "Credential store is not initialized")
    CredentialStoreException credentialStoreNotInitialized();

    @Message(id = 9, value = "Credential alias has to be provided")
    CredentialStoreException credentialAliasRequired();

    @Message(id = 10, value = "Credential cannot be null")
    CredentialStoreException credentialCannotBeNull();

    @Message(id = 11, value = "Credential alias must be in format 'path.key', got: %s")
    CredentialStoreException credentialAliasInvalidFormat(String credentialAlias);

    @Message(id = 12, value = "Failed to extract password from credential")
    CredentialStoreException failedToExtractPasswordFromCredential();

    @Message(id = 13, value = "Failed to store credential in vault")
    CredentialStoreException failedToStoreCredentialInVault(@Cause Exception e);

    @Message(id = 14, value = "Only PasswordCredential with ClearPassword is supported")
    UnsupportedCredentialTypeException onlyPasswordCredentialWithClearPasswordSupported(@Cause ClassCastException e);

    @Message(id = 15, value = "Failed to retrieve credential from vault")
    CredentialStoreException failedToRetrieveCredentialFromVault(@Cause Exception e);

    @Message(id = 16, value = "Requested credential type is not supported: %s")
    CredentialStoreException unsupportedCredentialType(String typeName, @Cause ClassCastException e);

    @Message(id = 17, value = "Failed to remove credential from vault")
    CredentialStoreException failedToRemoveCredentialFromVault(@Cause Exception e);

    @Message(id = 18, value = "Empty or null path provided to getAliases operation")
    CredentialStoreException emptyPathForGetAliases();

    @Message(id = 19, value = "recursive-depth must be non-negative, got: %s")
    CredentialStoreException recursiveDepthMustBeNonNegative(int recursiveDepth);

    @Message(id = 20, value = "maxNumberOfAliases must be positive, got: %s")
    CredentialStoreException maxNumberOfAliasesMustBePositive(int maxNumberOfAliases);

    @Message(id = 21, value = "Could not read keys from path \"%s\" (currentDepth=%d, recursive=%b), message is: %s")
    CredentialStoreException couldNotReadKeysFromPath(String path, int currentDepth, boolean recursive, String message,
            @Cause Exception e);

    @Message(id = 22, value = "Forbidden to list subpaths at path \"%s\"")
    CredentialStoreException forbiddenToListSubpathsAtCredentialStorePath(String path, @Cause Exception e);

    // --- Vault connector: operational logs ---

    @LogMessage(level = DEBUG)
    @Message(id = 23, value = "Vault configuration successful for URL: %s")
    void vaultConfigurationSuccessful(String vaultUrl);

    @LogMessage(level = ERROR)
    @Message(id = 24, value = "Failed to configure Vault connection to %s")
    void vaultConnectorConfigurationFailed(String vaultUrl, @Cause Throwable cause);

    @LogMessage(level = DEBUG)
    @Message(id = 25, value = "Unable to login with %s")
    void vaultLoginAttemptFailed(String strategyClassName, @Cause Throwable cause);

    @LogMessage(level = TRACE)
    @Message(id = 26, value = "Vault retrieved secret successfully from path: %s, url: %s")
    void vaultRetrievedSecret(String path, String vaultUrl);

    @LogMessage(level = TRACE)
    @Message(id = 27, value = "Key '%s' not found in secret at path: %s")
    void vaultKeyNotFoundInSecret(String key, String path);

    @LogMessage(level = TRACE)
    @Message(id = 28, value = "Forbidden to retrieve the secret from vault at path: %s")
    void vaultForbiddenToRetrieveSecret(String path);

    @LogMessage(level = TRACE)
    @Message(id = 29, value = "Secret not found at path: %s")
    void vaultSecretNotFoundAtPath(String path);

    @LogMessage(level = TRACE)
    @Message(id = 30, value = "Vault stored secret successfully at path: %s, url: %s")
    void vaultStoredSecret(String path, String vaultUrl);

    @LogMessage(level = TRACE)
    @Message(id = 31, value = "Key %s does not exist at path %s")
    void vaultKeyDoesNotExistAtPath(String key, String path);

    @LogMessage(level = TRACE)
    @Message(id = 32, value = "Vault deleted secret path successfully (no keys remaining): %s")
    void vaultDeletedSecretPath(String path);

    @LogMessage(level = TRACE)
    @Message(id = 33, value = "Vault removed key %s from path %s successfully")
    void vaultRemovedKeyFromPath(String key, String path);

    // --- Vault connector: Exception methods (return proper exception types, not third-party VaultException) ---

    @Message(id = 34, value = "All login strategies failed")
    CredentialStoreException vaultAllLoginStrategiesFailed();

    @Message(id = 35, value = "Alias cannot be null")
    CredentialStoreException vaultAliasCannotBeNull();

    @Message(id = 36, value = "Key cannot be null or empty")
    CredentialStoreException vaultKeyCannotBeNullOrEmpty();

    @Message(id = 37, value = "Value cannot be null")
    CredentialStoreException vaultValueCannotBeNull();

    @Message(id = 38, value = "Forbidden to retrieve secret at path: %s")
    CredentialStoreException vaultForbiddenToRetrieveSecretAtPath(String path);

    @Message(id = 39, value = "Failed to retrieve secret from path: %s/%s (HTTP %d)")
    CredentialStoreException vaultFailedToRetrieveSecretHttp(String path, String key, int responseStatus);

    @Message(id = 40, value = "Forbidden to store secret at path: %s")
    CredentialStoreException vaultForbiddenToStoreSecretAtPath(String path);

    @Message(id = 41, value = "Failed to store secret at path: %s/%s (HTTP %d)")
    CredentialStoreException vaultFailedToStoreSecretHttp(String path, String key, int responseStatus);

    @Message(id = 42, value = "Forbidden to delete secret at path: %s")
    CredentialStoreException vaultForbiddenToDeleteSecretAtPath(String path);

    @Message(id = 43, value = "Failed to delete secret at path: %s (HTTP %d)")
    CredentialStoreException vaultFailedToDeleteSecretHttp(String path, int deleteStatus);

    @Message(id = 44, value = "Forbidden to update secret at path: %s")
    CredentialStoreException vaultForbiddenToUpdateSecretAtPath(String path);

    @Message(id = 45, value = "Failed to update secret at path: %s after removing key %s (HTTP %d)")
    CredentialStoreException vaultFailedToUpdateSecretAfterRemoveKey(String path, String key, int writeStatus);

    @Message(id = 46, value = "Path does not exist or forbidden: \"%s\"")
    String vaultPathDoesNotExistOrForbidden(String path);

    @Message(id = 47, value = "Failed to read aliases on path: \"%s\"")
    String vaultFailedToReadAliasesOnPath(String path);

    @Message(id = 48, value = "Path not found in vault: \"%s\"")
    String vaultPathNotFoundInVault(String path);

    @Message(id = 49, value = "Forbidden to list subpaths at path: \"%s\"")
    String vaultForbiddenToListSubpathsAtPath(String path);

    @Message(id = 50, value = "Failed to list subpaths at path: \"%s\" (HTTP %d)")
    String vaultFailedToListSubpathsHttp(String path, int responseStatus);

    @Message(id = 51, value = "Unexpected response format when listing subpaths at path: \"%s\": %s")
    String vaultUnexpectedListSubpathsFormat(String path, String detail);

    // --- Login strategies & config ---

    @Message(id = 52, value = "Token is null, cannot login with token")
    String vaultTokenNullCannotLogin();

    @Message(id = 53, value = "JWT configuration is missing")
    String vaultJwtConfigurationMissing();

    @Message(id = 54, value = "Missing required property!")
    IllegalArgumentException jwtMissingRequiredProperty();

    @Message(id = 55, value = "VaultConnector cannot be null")
    IllegalArgumentException vaultConnectorCannotBeNull();

    @Message(id = 56, value = "Secret path cannot be null or empty")
    IllegalArgumentException vaultSecretPathInvalid();

    @Message(id = 57, value = "Secret key cannot be null or empty")
    IllegalArgumentException vaultSecretKeyInvalid();

    @Message(id = 58, value = "Failed to retrieve credential from Vault: %s")
    IOException failedToRetrieveCredentialFromVaultIo(String detail, @Cause Exception e);

    @Message(id = 59, value = "Unexpected test container output type %s")
    IllegalArgumentException unexpectedTestContainerOutputType(Object outputType);

    @Message(id = 60, value = "No authentication method configured: provide either a vault token (via credential-reference) or TLS client certificate authentication (via authentication-context)")
    CredentialStoreException noAuthenticationMethodConfigured();

    // --- Alias parsing errors ---

    @Message(id = 61, value = "Alias cannot be null or empty")
    CredentialStoreException aliasCannotBeNullOrEmpty();

    @Message(id = 62, value = "Invalid engine specification: missing delimiter after 'engine=' in alias: %s")
    CredentialStoreException invalidEngineSpecificationMissingDelimiter(String alias);

    @Message(id = 63, value = "Engine type cannot be empty in alias: %s")
    CredentialStoreException engineTypeCannotBeEmpty(String alias);

    @Message(id = 64, value = "Missing '#' delimiter after mount path in alias: %s")
    CredentialStoreException missingHashDelimiterAfterMountPath(String alias);

    @Message(id = 65, value = "Mount path cannot be empty after '@' in alias: %s")
    CredentialStoreException mountPathCannotBeEmpty(String alias);

    @Message(id = 66, value = "Secret path must start with '#' in alias: %s")
    CredentialStoreException secretPathMustStartWithHash(String alias);

    @Message(id = 67, value = "Missing '?' delimiter before key path in alias: %s")
    CredentialStoreException missingQuestionDelimiterBeforeKeyPath(String alias);

    @Message(id = 68, value = "Secret path cannot be empty in alias: %s")
    CredentialStoreException secretPathCannotBeEmpty(String alias);

    @Message(id = 69, value = "Key path cannot be empty in alias: %s")
    CredentialStoreException keyPathCannotBeEmpty(String alias);

    @Message(id = 70, value = "Key path cannot be null or empty")
    CredentialStoreException keyPathCannotBeNullOrEmpty();

    @Message(id = 71, value = "Key path contains empty segment: %s")
    CredentialStoreException keyPathContainsEmptySegment(String keyPath);

    // --- Legacy format support ---

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 72, value = "Legacy alias format detected: '%s'. This format is deprecated and will be removed in a future release. Please migrate to the new format: '%s'")
    void legacyAliasFormatDeprecated(String legacyAlias, String newFormatEquivalent);

    @Message(id = 73, value = "Legacy alias format '%s' is not supported. Use new format: '%s'")
    CredentialStoreException legacyAliasFormatNotSupported(String legacyAlias, String newFormatEquivalent);

    @Message(id = 74, value = "Invalid alias format: %s. Expected format: [engine=TYPE][@mount-path][#]secret-path?key-path (# is optional when no engine= or @ prefix)")
    CredentialStoreException invalidAliasFormat(String alias);

    @Message(id = 75, value = "Invalid engine type '%s'. Valid values are: KVv1, KVv2")
    CredentialStoreException invalidEngineType(String engineType);

    @Message(id = 76, value = "Invalid default-engine-type configuration '%s'. Valid values are: KVv1, KVv2")
    CredentialStoreException invalidDefaultEngineType(String engineType);

    // --- Deep nesting warning ---

    @LogMessage(level = WARN)
    @Message(id = 77, value = "Key path '%s' has deep nesting (%d levels). Consider flattening the JSON structure for better performance and maintainability.")
    void deepKeyPathNesting(String keyPath, int nestingLevel);

    @Message(id = 78, value = "Could not list secrets at path '%s' (HTTP status: %d)")
    CredentialStoreException couldNotListSecretsAtPath(String path, int httpStatus);

    @Message(id = 79, value = "Could not list secrets at path '%s'")
    CredentialStoreException couldNotListSecretsAtPath(String path, @Cause Exception e);

    @Message(id = 80, value = "Legacy path format '%s' is not supported when supportLegacyAliasFormat is disabled. Use '@mount#secretpath' or '#secretpath' format instead.")
    CredentialStoreException legacyPathFormatNotSupported(String path);

    @Message(id = 81, value = "Failed to build Vault TLS configuration")
    IOException failedToBuildVaultTlsConfiguration(@Cause Exception e);
}
