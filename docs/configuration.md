# Configuration Guide

## Overview

This guide describes all configuration parameters for the WildFly Elytron HashiCorp Vault credential store. The credential store integrates with HashiCorp Vault to securely retrieve credentials for use in WildFly applications.

## Configuration Parameters

### Required Parameters

#### `host-address`
- **Type:** String (URL)
- **Required:** Yes
- **Description:** The base URL of the HashiCorp Vault server
- **Format:** `protocol://host:port`
- **Examples:**
  ```
  https://vault.example.com:8200
  http://localhost:8200
  https://vault.company.internal
  ```

### Optional Parameters

#### `namespace`
- **Type:** String
- **Required:** No
- **Default:** None (root namespace)
- **Description:** The Vault namespace to use (Vault Enterprise feature)
- **Examples:**
  ```
  engineering
  team/backend
  prod/services
  ```
- **Notes:**
  - Only available in Vault Enterprise
  - Namespaces provide multi-tenancy within a single Vault instance
  - Leave unset to use the root namespace

#### `trust-store-path`
- **Type:** String (file path)
- **Required:** No
- **Default:** System default trust store
- **Description:** Path to a custom trust store for TLS certificate verification
- **Examples:**
  ```
  /etc/pki/trust/vault-ca.jks
  ${jboss.server.config.dir}/vault-truststore.jks
  ```
- **Notes:**
  - Used when Vault server uses a custom CA certificate
  - Must be in JKS or PKCS12 format
  - Requires `trust-store-pass` if the trust store is password-protected

#### `trust-store-pass`
- **Type:** String (password)
- **Required:** No (required if `trust-store-path` is set and password-protected)
- **Default:** None
- **Description:** Password for the trust store
- **Security Note:** Consider using credential references or vault expressions for this value

#### `key-store-path`
- **Type:** String (file path)
- **Required:** No
- **Default:** None
- **Description:** Path to a key store for mutual TLS authentication
- **Examples:**
  ```
  /etc/pki/client/vault-client.jks
  ${jboss.server.config.dir}/vault-keystore.jks
  ```
- **Notes:**
  - Used when Vault requires client certificate authentication
  - Must be in JKS or PKCS12 format
  - Requires `key-store-pass`

#### `key-store-pass`
- **Type:** String (password)
- **Required:** No (required if `key-store-path` is set)
- **Default:** None
- **Description:** Password for the key store
- **Security Note:** Consider using credential references or vault expressions for this value

#### `support-legacy-alias-format`
- **Type:** Boolean
- **Required:** No
- **Default:** `false` (legacy format disabled)
- **Description:** Enable support for the legacy alias format (`secret-path.key`)
- **Values:**
  - `true` - Support both new and legacy formats
  - `false` - Only support new format
- **Examples:**
  ```xml
  <attribute name="support-legacy-alias-format" value="true"/>
  <attribute name="support-legacy-alias-format" value="false"/>
  ```
- **Notes:**
  - Legacy format: `myapp/database.password`
  - New format: `myapp/database?password`
  - See [migration.md](migration.md) for migration guidance
  - Legacy format will be deprecated in future releases

#### `default-engine-type`
- **Type:** String (enum)
- **Required:** No
- **Default:** `KVv2`
- **Description:** Default Vault secret engine type when not specified in alias
- **Valid Values:**
  - `KVv1` - Key-Value version 1 (for legacy Vault configurations)
  - `KVv2` - Key-Value version 2 (default, recommended)
- **Examples:**
  ```xml
  <attribute name="default-engine-type" value="KVv2"/>
  <attribute name="default-engine-type" value="KVv1"/>
  ```
- **Notes:**
  - Can be overridden per-alias using `engine=TYPE` prefix
  - KVv2 is recommended for most use cases

#### `default-mount-path`
- **Type:** String
- **Required:** No
- **Default:** `secret`
- **Description:** Default mount path when not specified in alias
- **Examples:**
  ```xml
  <attribute name="default-mount-path" value="secret"/>
  <attribute name="default-mount-path" value="prod/secrets"/>
  <attribute name="default-mount-path" value="team/backend"/>
  ```
- **Notes:**
  - Can be overridden per-alias using `@mount-path` prefix
  - Must match the mount path configured in Vault

## Configuration Examples

### Basic Configuration

Minimal configuration for a local Vault instance:

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="http://localhost:8200"/>
    </implementation-properties>
</credential-store>
```

### Production Configuration with TLS

Configuration with custom CA certificate:

When no `SSLContext` is supplied programmatically, initialization loads the configured stores and builds the TLS configuration. An incorrect store password fails initialization with a `CredentialStoreException` identifying the key store or trust store. HTTPS validates the server certificate and connection hostname; the first remote operation verifies connectivity and authentication.

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="trust-store-path" value="${jboss.server.config.dir}/vault-ca.jks"/>
        <property name="trust-store-pass" value="changeit"/>
    </implementation-properties>
</credential-store>
```

### Mutual TLS Configuration

Configuration with client certificate authentication:

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="trust-store-path" value="${jboss.server.config.dir}/vault-ca.jks"/>
        <property name="trust-store-pass" value="changeit"/>
        <property name="key-store-path" value="${jboss.server.config.dir}/vault-client.jks"/>
        <property name="key-store-pass" value="clientpass"/>
    </implementation-properties>
</credential-store>
```

### Enterprise Configuration with Namespace

Configuration for Vault Enterprise with namespace:

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="namespace" value="engineering/backend"/>
        <property name="trust-store-path" value="${jboss.server.config.dir}/vault-ca.jks"/>
        <property name="trust-store-pass" value="changeit"/>
    </implementation-properties>
</credential-store>
```

### Custom Defaults Configuration

Configuration with custom engine type and mount path:

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="default-engine-type" value="KVv1"/>
        <property name="default-mount-path" value="prod/secrets"/>
        <property name="trust-store-path" value="${jboss.server.config.dir}/vault-ca.jks"/>
        <property name="trust-store-pass" value="changeit"/>
    </implementation-properties>
</credential-store>
```

### Migration Configuration

Configuration with legacy format support enabled:

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="support-legacy-alias-format" value="true"/>
        <property name="trust-store-path" value="${jboss.server.config.dir}/vault-ca.jks"/>
        <property name="trust-store-pass" value="changeit"/>
    </implementation-properties>
</credential-store>
```

## Common Configuration Patterns

### Development Environment

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="http://localhost:8200"/>
        <property name="support-legacy-alias-format" value="true"/>
    </implementation-properties>
</credential-store>
```

**Notes:**
- Uses HTTP (not recommended for production)
- No TLS configuration needed
- Legacy format support for easier migration

### Staging Environment

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault-staging.company.com:8200"/>
        <property name="default-mount-path" value="staging/secrets"/>
        <property name="trust-store-path" value="${jboss.server.config.dir}/vault-ca.jks"/>
        <property name="trust-store-pass" value="changeit"/>
        <property name="support-legacy-alias-format" value="true"/>
    </implementation-properties>
</credential-store>
```

**Notes:**
- Uses HTTPS with custom CA
- Custom mount path for staging secrets
- Legacy format support during migration period

### Production Environment

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="namespace" value="production"/>
        <property name="default-mount-path" value="prod/secrets"/>
        <property name="trust-store-path" value="${jboss.server.config.dir}/vault-ca.jks"/>
        <property name="trust-store-pass" value="${CREDENTIAL_STORE_PASS}"/>
        <property name="key-store-path" value="${jboss.server.config.dir}/vault-client.jks"/>
        <property name="key-store-pass" value="${CLIENT_CERT_PASS}"/>
        <property name="support-legacy-alias-format" value="false"/>
    </implementation-properties>
</credential-store>
```

**Notes:**
- Uses HTTPS with mutual TLS
- Vault Enterprise namespace
- Passwords from environment variables
- Legacy format disabled (new format only)

## Security Best Practices

### 1. Always Use HTTPS in Production
```xml
<property name="host-address" value="https://vault.company.com:8200"/>
```

### 2. Use Custom CA Certificates
```xml
<property name="trust-store-path" value="${jboss.server.config.dir}/vault-ca.jks"/>
<property name="trust-store-pass" value="changeit"/>
```

### 3. Consider Mutual TLS for Production
```xml
<property name="key-store-path" value="${jboss.server.config.dir}/vault-client.jks"/>
<property name="key-store-pass" value="clientpass"/>
```

### 4. Protect Sensitive Configuration Values
Use environment variables or credential references for passwords:
```xml
<property name="trust-store-pass" value="${VAULT_TRUSTSTORE_PASS}"/>
<property name="key-store-pass" value="${VAULT_KEYSTORE_PASS}"/>
```

### 5. Use Namespaces for Multi-Tenancy
```xml
<property name="namespace" value="team/application"/>
```

### 6. Disable Legacy Format After Migration
```xml
<property name="support-legacy-alias-format" value="false"/>
```

## Troubleshooting

### Connection Issues

**Problem:** Cannot connect to Vault server

**Solutions:**
1. Verify `host-address` is correct and accessible
2. Check network connectivity: `curl https://vault.company.com:8200/v1/sys/health`
3. Verify TLS certificates if using HTTPS
4. Check firewall rules

### TLS Certificate Issues

**Problem:** SSL/TLS handshake failures

**Solutions:**
1. Verify `trust-store-path` points to correct file
2. Ensure trust store contains Vault server's CA certificate
3. Check `trust-store-pass` is correct
4. Verify certificate hasn't expired

### Authentication Issues

**Problem:** Authentication failures

**Solutions:**
1. Verify Vault token is valid and not expired
2. Check token has appropriate policies
3. Verify namespace is correct (if using Vault Enterprise)
4. Ensure mount path exists in Vault

### Alias Format Issues

**Problem:** Aliases not resolving correctly

**Solutions:**
1. Check alias format matches specification (see [alias-format.md](alias-format.md))
2. Verify `default-engine-type` matches your Vault configuration
3. Verify `default-mount-path` matches your Vault mount
4. Enable `support-legacy-alias-format` if using old format
5. Check for URL-encoding issues in paths

## See Also

- [Alias Format Specification](alias-format.md) - Detailed alias format documentation
- [Migration Guide](migration.md) - Migrating from legacy format
- [WildFly Elytron Documentation](https://docs.wildfly.org/elytron/)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)