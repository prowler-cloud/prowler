# Microsoft 365 authentication

By default Prowler uses MsGraph Python SDK identity package authentication methods using the class `ClientSecretCredential`.
This allows Prowler to authenticate against Microsoft 365 using the following methods:

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

To use Prowler you need to set up also the permissions required to access your resources in your Microsoft 365 account, to more details refer to [Requirements](../../getting-started/requirements.md#microsoft-365)
