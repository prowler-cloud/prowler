# Microsoft 365 Authentication for Prowler

By default, Prowler utilizes the MsGraph Python SDK identity package for authentication, leveraging the class `ClientSecretCredential`. This enables authentication against Microsoft 365 using the following approaches:

    - Service principal authentication via environment variables (Enterprise Application)
    - Currently stored CLI credentials
    - Interactive browser authentication

Before launching the tool, specify the desired authentication method using the following flags:

```console
# Service principal authentication:
prowler microsoft365 --sp-env-auth

# CLI authentication
prowler microsoft365 --az-cli-auth

# Browser authentication
prowler microsoft365 --browser-auth --tenant-id "XXXXXXXX"
```

## Permission Configuration

To ensure Prowler can access the required resources within your Microsoft 365 account, proper permissions must be configured. Refer to the [Requirements](../../getting-started/requirements.md) section for details on setting up necessary privileges.
