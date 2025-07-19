# Authentication Guide: JWT Tokens vs API Keys

This guide explains the two primary authentication methods available in Prowler: JWT tokens and API keys. Understanding when and how to use each method is crucial for securing your Prowler deployment and integrating with external systems.

## Overview

Prowler supports two distinct authentication mechanisms:

- **JWT Tokens**: Short-lived, secure tokens designed for interactive user sessions
- **API Keys**: Long-lived credentials designed for programmatic access and automation

Both methods provide secure access to the Prowler API, but they serve different purposes and have distinct security characteristics.

## JWT Tokens

### What are JWT Tokens?

JSON Web Tokens (JWT) are industry-standard tokens (RFC 7519) that securely transmit information between parties. In Prowler, JWT tokens are used for interactive user authentication and session management.

### Key Characteristics

- **Algorithm**: RS256 (RSA Signature with SHA-256)
- **Structure**: Header.Payload.Signature (standard JWT format)
- **Access Token Lifetime**: 30 minutes (configurable via `DJANGO_ACCESS_TOKEN_LIFETIME`)
- **Refresh Token Lifetime**: 24 hours (configurable via `DJANGO_REFRESH_TOKEN_LIFETIME`)
- **Token Rotation**: Enabled with automatic blacklisting of old tokens
- **Claims**: Includes `user_id`, `tenant_id`, `exp`, `iat`, `nbf`, `jti`, `aud`, `iss`

### Authentication Format

```http
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
```

### When to Use JWT Tokens

✅ **Recommended for:**

- Interactive web applications
- User-facing dashboards and UIs
- Mobile applications with user interfaces
- Short-duration API access
- Applications requiring automatic token refresh

❌ **Not recommended for:**

- Long-running scripts or automation
- Server-to-server communication
- CI/CD pipelines
- Scheduled tasks or cron jobs
- Applications without refresh capability

### Security Features

- **Short-lived access tokens** reduce exposure window
- **Automatic token rotation** prevents token reuse
- **RSA signing** ensures token integrity
- **Token blacklisting** prevents replay attacks after refresh
- **Standard JWT claims** for proper validation

### Obtaining JWT Tokens

#### Via API

```bash
curl -X POST https://api.prowler.com/api/v1/tokens \
  -H "Content-Type: application/vnd.api+json" \
  -d '{
    "data": {
      "type": "tokens",
      "attributes": {
        "email": "user@example.com",
        "password": "your-secure-password",
        "tenant_id": "optional-tenant-uuid"
      }
    }
  }'
```

#### Response

```json
{
  "data": {
    "type": "tokens",
    "attributes": {
      "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
      "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
    }
  }
}
```

### Token Refresh

When access tokens expire, use the refresh token:

```bash
curl -X POST https://api.prowler.com/api/v1/tokens/refresh \
  -H "Content-Type: application/vnd.api+json" \
  -d '{
    "data": {
      "type": "tokens-refresh",
      "attributes": {
        "refresh": "your-refresh-token"
      }
    }
  }'
```

## API Keys

### What are API Keys?

API Keys are long-lived credentials designed for programmatic access to the Prowler API. They provide a simple authentication mechanism for automation, scripts, and server-to-server communication.

### Key Characteristics

- **Format**: `pk_<8-char-prefix>.<32-char-random>` (e.g., `pk_a1b2c3d4.xyz789...`)
- **Storage**: Hashed using Django's secure password hashing (never stored in plaintext)
- **Lifetime**: Configurable expiration (1 day, 7 days, 30 days, 90 days, or never)
- **Revocation**: Can be immediately revoked
- **Audit Trail**: Tracks last used timestamp and IP address

### Authentication Format

```http
Authorization: ApiKey pk_a1b2c3d4.xyz789abcdef...
```

### When to Use API Keys

✅ **Recommended for:**
- Automation scripts and CI/CD pipelines
- Server-to-server communication
- Long-running processes
- Scheduled tasks and cron jobs
- Command-line tools and SDKs
- Integration with monitoring systems
- Batch processing applications

❌ **Not recommended for:**
- Interactive user applications
- Client-side applications (browsers, mobile apps)
- Applications where tokens can be exposed
- Short-duration tasks (where JWT tokens would suffice)

### Security Features

- **Unique prefix-based lookup** for performance and collision avoidance
- **Secure hashing** using Django's password hashing algorithms
- **Comprehensive audit logging** including usage tracking
- **One-time display** during creation with security warnings

### Creating API Keys

#### Via Web UI

1. Navigate to your user profile
2. Go to the "API Keys" section
3. Click "Create New Key"
4. Provide a descriptive name
5. Select expiration period
6. **Important**: Copy the key immediately - it won't be shown again

#### Via API

```bash
curl -X POST https://api.prowler.com/api/v1/users/{user-id}/api-keys \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/vnd.api+json" \
  -d '{
    "data": {
      "type": "api-keys",
      "attributes": {
        "name": "CI/CD Pipeline Key",
        "expires_at": "2024-12-31T23:59:59Z"
      }
    }
  }'
```

## Permission Scopes and Access Control

Both JWT tokens and API keys inherit the same permission scopes from the associated user account through Prowler's Role-Based Access Control (RBAC) system.

### Permission Types

- **`MANAGE_USERS`**: Create, update, and manage user accounts
- **`MANAGE_ACCOUNT`**: Modify account settings and configurations
- **`MANAGE_BILLING`**: Access billing and subscription information
- **`MANAGE_PROVIDERS`**: Add and configure cloud providers
- **`MANAGE_INTEGRATIONS`**: Set up and manage third-party integrations
- **`MANAGE_SCANS`**: Trigger and manage security scans
- **`UNLIMITED_VISIBILITY`**: Bypass data filtering

### Scope Inheritance

```mermaid
graph TD
    A[User Account] --> B[Role Assignment]
    B --> C[Permission Scopes]
    C --> D[JWT Token]
    C --> E[API Key]
    D --> F[API Access]
    E --> F
```

### Tenant Isolation

Both authentication methods enforce tenant-level isolation:

- Users can only access resources within their assigned tenants
- Cross-tenant access is strictly prohibited
- Tenant ID is embedded in JWT tokens and associated with API keys

## Security Best Practices

### For JWT Tokens

1. **Implement Proper Refresh Logic**

   ```javascript
   // Example refresh implementation
   if (tokenExpired(accessToken)) {
     const newTokens = await refreshToken(refreshToken);
     // Update stored tokens
   }
   ```

2. **Secure Token Storage**
   - Store tokens in secure, httpOnly cookies when possible
   - Use secure session storage for browser applications
   - Never log or expose tokens in client-side code

3. **Handle Expiration Gracefully**
   - Implement automatic retry with token refresh
   - Provide clear error messages for authentication failures
   - Log out users when refresh tokens expire

## Limitations and Considerations

### JWT Token Limitations

- **Short Lifespan**: Requires active refresh mechanism
- **Size**: Larger than simple API keys (contains claims)
- **Complexity**: Requires JWT library support for validation
- **Refresh Dependency**: Applications must handle refresh token rotation

### API Key Limitations

- **One-Time Display**: Lost keys cannot be recovered, only replaced
- **Long-Term Exposure**: Higher risk if compromised due to longer lifetime
- **Revocation Only**: Cannot be temporarily disabled, only permanently revoked

### Performance Considerations

- **JWT Tokens**: No database lookup required for validation (stateless)
- **API Keys**: Require database lookup for verification (stateful)

## Migration and Integration Patterns

### From API Keys to JWT Tokens

When moving from automation to interactive applications:

1. Implement JWT token handling in your application
2. Add refresh logic and proper error handling
3. Update authentication headers
4. Test token expiration scenarios
5. Gradually phase out API key usage

### From JWT Tokens to API Keys

When moving from interactive to automated access:

1. Create API keys with appropriate expiration
2. Update authentication headers to use ApiKey format
3. Store keys securely in environment variables

## Troubleshooting

### Common JWT Token Issues

**Problem**: Tokens expire too quickly
**Solution**: Adjust `DJANGO_ACCESS_TOKEN_LIFETIME` or implement proper refresh logic

**Problem**: Refresh tokens are invalid
**Solution**: Check if token rotation is causing issues; ensure proper token storage

**Problem**: Invalid signature errors
**Solution**: Verify `DJANGO_TOKEN_SIGNING_KEY` and `DJANGO_TOKEN_VERIFYING_KEY` configuration

### Common API Key Issues

**Problem**: API key always returns 401
**Solution**: Verify key format and ensure it hasn't been revoked or expired

**Problem**: Key not working after creation
**Solution**: Ensure the key was copied correctly during the one-time display

## Environment Configuration

### Required Environment Variables

```bash
# JWT Token Configuration
DJANGO_TOKEN_SIGNING_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
DJANGO_TOKEN_VERIFYING_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
DJANGO_ACCESS_TOKEN_LIFETIME=30  # minutes
DJANGO_REFRESH_TOKEN_LIFETIME=1440  # minutes (24 hours)

# Cache Configuration
VALKEY_HOST=valkey
VALKEY_PORT=6379
VALKEY_CACHE_DB=1
```

## Conclusion

Choose your authentication method based on your use case:

- **Use JWT Tokens** for interactive applications, web UIs, and short-term API access
- **Use API Keys** for automation, CI/CD, server-to-server communication, and long-running processes

Both methods provide robust security when implemented correctly. Follow the security best practices outlined in this guide, implement proper error handling, and monitor usage patterns to maintain a secure Prowler deployment.

For additional support or questions about authentication, refer to the [API documentation](../api/) or contact the Prowler support team. 