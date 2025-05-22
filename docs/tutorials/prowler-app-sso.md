# Configuring SAML Single Sign-On (SSO) in Prowler

This guide explains how to enable and test SAML SSO integration in Prowler. It includes environment setup, certificate configuration, API endpoints, and how to configure Okta as your Identity Provider (IdP).

---

## 🧾 Environment Configuration

### `DJANGO_ALLOWED_HOSTS`

Update this variable to specify which domains Django should accept incoming requests from. This typically includes:

- `localhost` for local development
- container hostnames (e.g. `prowler-api`)
- public-facing domains or tunnels (e.g. ngrok)

**Example**:

```env
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,prowler-api,mycompany.prowler
```

# SAML Certificates

To enable SAML support, you must provide a public certificate and private key to allow Prowler to sign SAML requests and validate responses.

### Why is this necessary?

SAML relies on digital signatures to verify trust between the Identity Provider (IdP) and the Service Provider (SP). Prowler acts as the SP and must use a certificate to sign outbound authentication requests.

### Add to your .env file:

```env
SAML_PUBLIC_CERT="-----BEGIN CERTIFICATE-----
...your certificate here...
-----END CERTIFICATE-----"

SAML_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
...your private key here...
-----END PRIVATE KEY-----"
```

# SAML Configuration API

You can manage SAML settings via the API. Prowler provides full CRUD support for tenant-specific SAML configuration.

- GET /api/v1/saml-config: Retrieve the current configuration

- POST /api/v1/saml-config:Create a new configuration

- PATCH /api/v1/saml-config: Update the existing configuration

- DELETE /api/v1/saml-config: Remove the current configuration


???+ note "API Note"
    SSO with SAML API documentation.[Prowler API Reference - Upload SAML configuration](https://api.prowler.com/api/v1/docs#tag/SAML/operation/saml_config_create)
