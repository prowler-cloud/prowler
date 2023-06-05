# Azure authentication

By default Prowler uses Azure Python SDK identity package authentication methods using the classes `DefaultAzureCredential` and `InteractiveBrowserCredential`.
This allows Prowler to authenticate against azure using the following methods:

- Service principal authentication by environment variables (Enterprise Application)
- Current AZ CLI credentials stored
- Interactive browser authentication
- Managed identity authentication

To launch the tool it is required to specify which method is used through the following flags:

```console
# To use service principal authentication
prowler azure --sp-env-auth

# To use az cli authentication
prowler azure --az-cli-auth

# To use browser authentication
prowler azure --browser-auth --tenant-id "XXXXXXXX"

# To use managed identity auth
prowler azure --managed-identity-auth
```

To use Prowler you need to set up also the permissions required to access your resources in your Azure account, to more details refer to [Requirements](/getting-started/requirements)
