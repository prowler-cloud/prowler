# Microsoft 365 Authentication for Prowler

By default, Prowler utilizes the MsGraph Python SDK identity package for authentication, leveraging the class `ClientSecretCredential`. This enables authentication against Microsoft 365 using the following approaches:

- Service principal authentication by environment variables (Enterprise Application)
- Service principal and Microsoft user credentials by environment variabled (using PowerShell requires this authentication method)
- Current CLI credentials stored
- Interactive browser authentication


To launch the tool first you need to specify which method is used through the following flags:

```console
# To use service principal (app) authentication and Microsoft user credentials (to use PowerShell)
prowler m365 --env-auth

# To use service principal authentication
prowler m365 --sp-env-auth

# To use cli authentication
prowler m365 --az-cli-auth

# To use browser authentication
prowler m365 --browser-auth --tenant-id "XXXXXXXX"
```

## Permission Configuration

To ensure Prowler can access the required resources within your Microsoft 365 account, proper permissions must be configured. Refer to the [Requirements](../../getting-started/requirements.md) section for details on setting up necessary privileges.
