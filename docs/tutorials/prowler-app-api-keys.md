# API Keys

Prowler App provides API key authentication as an alternative to JWT tokens, enabling programmatic access to the Prowler API for automation, CI/CD pipelines, and third-party integrations. This comprehensive guide demonstrates how to create, manage, and securely use API keys to authenticate with the Prowler API.

Using API keys with Prowler App provides:

* **Programmatic access:** Enable automated workflows and scripts to interact with Prowler
* **Long-lived authentication:** Create keys with optional expiration dates (default: 1 year)
* **Granular control:** Manage multiple keys with different names and purposes
* **Secure automation:** Safely integrate Prowler into CI/CD pipelines and infrastructure-as-code

## How It Works

API keys provide a secure authentication mechanism for accessing the Prowler API:

1. API keys are created through the Prowler App interface with a user-defined name and optional expiration date
2. The full API key is displayed **only once** upon creation - it cannot be retrieved later
3. Each API key consists of a prefix (visible in the UI) and an encrypted secret portion
4. API keys are used in the `Authorization` header with the format: `Authorization: Api-Key <your-api-key>`
5. The system tracks usage by updating the last used timestamp on each authenticated request
6. API keys automatically inherit the RBAC permissions of the user who created them (see [Permission Inheritance](#permission-inheritance))
7. API keys can be revoked at any time to immediately disable access

!!! note "Authentication Priority"
    If both a JWT token and an API key are present in the same request, the JWT token will be used for authentication by default.

!!! warning "Security Notice"
    API keys are equivalent to passwords and provide full access to your Prowler tenant with the permissions of the user who created them. Treat them with the same level of security as passwords.

## Required Permissions

To create, view, or manage API keys, you must have the **MANAGE_ACCOUNT** RBAC permission in your tenant. This permission controls access to all API key management operations.

If you don't have this permission, the API Keys section will not be accessible. Contact your tenant administrator to request access if needed.

For more information about RBAC permissions, refer to the [Prowler App RBAC documentation](./prowler-app-rbac.md).

## Creating API Keys

To create a new API key in Prowler App:

1. Navigate to **Settings** → **API Keys** in the Prowler App interface
2. Click the **Create API Key** button

    ![API Keys list](./img/api-keys/api-keys-list.png)

3. Configure the API key settings:
    * **Name:** Enter a descriptive name to identify this API key (minimum 3 characters, e.g., "CI Pipeline Production", "Monitoring Script")
    * **Expiration Date (optional):** Set a custom expiration date for the key. If not specified, the key will automatically expire **1 year (365 days)** from the creation date. After this date, the key will no longer authenticate

    ![Create API key form](./img/api-keys/create-api-key-form.png)

4. Click **Create** to generate the API key
5. **Important:** Copy and securely store the API key immediately. The full key is displayed only once and cannot be retrieved later

    ![API key created successfully](./img/api-keys/api-key-created.png)

!!! warning "Save Your API Key Immediately"
    After closing the creation dialog, only the key prefix will be visible in the interface. The full API key cannot be retrieved again. If you lose the key, you must create a new one and update your applications.

## Managing API Keys

### Viewing API Keys

The API Keys management interface displays all keys associated with your user account:

1. Navigate to **Settings** → **API Keys**
2. View the list of API keys with the following information:
    * **Name:** The descriptive name you assigned to the key
    * **Prefix:** The visible portion of the key for identification (e.g., `pk_abc12345`)
    * **Created:** Timestamp when the key was created
    * **Expires At:** The expiration date (if set)
    * **Last Used At:** Timestamp of the most recent successful authentication using this key
    * **Revoked:** Whether the key is currently active or has been revoked

    ![API Keys management interface](./img/api-keys/api-keys-management.png)

### Updating API Keys

API keys support limited updates to maintain security:

1. Locate the API key you want to modify in the list
2. Click the **Edit** button or action menu
3. **Updatable field:**
    * **Name:** Change the descriptive name for better identification
4. **Non-updatable fields:**
    * Prefix, expiration date, and the secret key itself cannot be modified
    * To change these properties, you must create a new API key and revoke the old one

5. Click **Save** to apply changes

    ![Update API key name](./img/api-keys/update-api-key.png)

### Actions

Each API key provides management actions through dedicated buttons or the action menu:

| Action | Purpose | Effect | Notes |
|--------|---------|--------|-------|
| **Edit Name** | Update the key's descriptive name | Changes the display name only | Does not affect authentication |
| **Revoke** | Disable the API key | Sets revoked status to true, blocking all authentication | Maintains audit trail and key history |

!!! note "API Keys Cannot Be Deleted"
    For security and audit purposes, API keys cannot be permanently deleted from the system. Instead, use the **Revoke** action to disable a key. Revoked keys remain visible in the interface for audit purposes but cannot be used for authentication.

## Permission Inheritance

API keys automatically inherit the RBAC permissions of the user who created them. This ensures that programmatic access maintains the same security boundaries as user access.

### How Permission Inheritance Works

* **Current permissions apply:** When an API key is used, it operates with the same RBAC permissions that the creating user currently has
* **Dynamic updates:** If the user's permissions change, the API key permissions are automatically updated to match
* **User downgrade:** If a user has their permissions reduced, all of their API keys will also have reduced permissions
* **Tenant removal:** If a user is removed from a tenant, all of their API keys for that tenant are **automatically revoked**
* **User deletion:** If a user is deleted from the application entirely, all of their API keys are **automatically revoked**

!!! warning "Automatic Revocation"
    API keys are automatically revoked when:

    - The user who created the key is removed from the tenant
    - The user who created the key is deleted from the application

    This ensures that access is immediately terminated when user access is revoked.

### Best Practices for Permission Management

* **Use service accounts for automation** - Create dedicated user accounts for API-based automation to separate human and programmatic access, ensuring API keys persist when team members leave
* **Review API key ownership regularly** - Ensure API keys are associated with appropriate user accounts and document ownership
* **Monitor permission changes** - Be aware that changing a user's permissions will affect all of their API keys
* **Plan for user offboarding** - Create replacement API keys under service accounts before removing users to avoid disruptions

## Security Best Practices

### Key Storage and Management

* **Never commit API keys to version control** - Add them to `.gitignore` and use environment variables or secure secret management systems
* **Use secret managers** - Store keys in tools like AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, or GitHub Secrets
* **Rotate keys regularly** - Create new keys and revoke old ones periodically as part of your security hygiene
* **Set expiration dates** - Use expiration dates to enforce automatic key rotation and reduce risk
* **Monitor last used timestamps** - Regularly review when keys were last used to identify unused or potentially compromised keys

### Key Usage

* **Create dedicated keys per application** - Use separate keys for different services, environments, or purposes
* **Use descriptive names** - Name keys clearly like "ci-pipeline-prod", "monitoring-staging", or "terraform-automation"
* **Limit key distribution** - Only share keys with team members who absolutely need them
* **Revoke immediately on breach** - If a key is exposed or compromised, revoke it immediately and create a new one

### Environment Variables

Store API keys in environment variables rather than hardcoding them in scripts or configuration files. Use platform-specific secret management systems (GitHub Secrets, GitLab CI/CD Variables, AWS Secrets Manager, HashiCorp Vault, etc.) for production environments.

### CI/CD Integration Best Practices

When using API keys in CI/CD pipelines:

* **Use pipeline secrets:** Store keys in your CI/CD platform's secret management system
* **Mask in logs:** Ensure your CI/CD platform automatically masks the API key in build logs
* **Create pipeline-specific keys:** Use separate keys for each pipeline or environment (dev, staging, production)
* **Set shorter expirations:** Use shorter expiration periods (e.g., 90 days) for automated systems to enforce rotation
* **Use service accounts:** Create dedicated user accounts for CI/CD pipelines (see [Permission Inheritance](#permission-inheritance) for details on automatic revocation)

## Troubleshooting

### Authentication fails with "Invalid API Key"

* Verify the API key is copied correctly with no extra spaces, line breaks, or hidden characters
* Ensure the key has not been revoked (check the Revoked column in the API Keys list)
* Check that the key has not expired (review the Expires At date)
* Confirm you're using the correct API key format with both prefix and secret portions
* Verify the key prefix matches what's displayed in the Prowler App interface

### API key not working after creation

* Verify you copied the full API key from the creation dialog, including both the prefix and encrypted portions
* Check that the key hasn't expired by reviewing the expiration date in the management interface
* Ensure the key is not revoked by checking its status in the API Keys list
* Confirm you're authenticating against the correct Prowler API environment

### Last used timestamp not updating

* The timestamp only updates on successful authentication requests
* If authentication fails, the timestamp will not be updated
* Verify your requests are completing successfully (not returning authentication errors)
* Check that the request is reaching the Prowler API and not being blocked by network policies

### Need to retrieve a lost API key

* API keys cannot be retrieved after the creation dialog is closed for security reasons
* You must create a new API key to replace the lost one
* Update all applications and scripts that use the old key with the new key
* Revoke the old key after confirming the new key works to prevent security issues
* Consider using a secret management system to prevent future loss

### Key was exposed or compromised

1. Immediately revoke the compromised key through the API Keys management interface
2. Review recent activity for any unauthorized access using the Last Used At timestamps
3. Create a new API key with a different name to replace the compromised one
4. Update all legitimate applications with the new key
5. Investigate how the key was exposed to prevent future incidents
6. Consider implementing additional security measures or using service accounts for better isolation
