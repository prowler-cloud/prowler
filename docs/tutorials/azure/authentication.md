# Azure Authentication in Prowler

By default, Prowler utilizes the Azure Python SDK identity package for authentication, leveraging the classes `DefaultAzureCredential` and `InteractiveBrowserCredential`. This enables authentication against Azure using the following approaches:

- Service principal authentication via environment variables (Enterprise Application)
- Currently stored AZ CLI credentials
- Interactive browser authentication
- Managed identity authentication

Before launching the tool, specify the desired method using the following flags:

```console
# Service principal authentication:
prowler azure --sp-env-auth

# AZ CLI authentication
prowler azure --az-cli-auth

# Browser authentication
prowler azure --browser-auth --tenant-id "XXXXXXXX"

# Managed identity authentication
prowler azure --managed-identity-auth
```

## Permission Configuration

To ensure Prowler can access the required resources within your Azure account, proper permissions must be configured. Refer to the [Requirements](../../getting-started/requirements.md) section for details on setting up necessary privileges.
