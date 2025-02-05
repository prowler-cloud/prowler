# Microsoft365 authentication

By default Prowler uses MsGraph Python SDK identity package authentication methods using the class `ClientSecretCredential`.
This allows Prowler to authenticate against microsoft365 using the following methods:

- Service principal authentication by environment variables (Enterprise Application)
- Current CLI credentials stored
- Interactive browser authentication

To launch the tool first you need to specify which method is used through the following flags:

```console
# To use service principal authentication
prowler microsoft365 --sp-env-auth

# To use cli authentication
prowler microsoft365 --az-cli-auth

# To use browser authentication
prowler microsoft365 --browser-auth --tenant-id "XXXXXXXX"
To use Prowler you need to set up also the permissions required to access your resources in your Microsoft365 account, to more details refer to [Requirements](../../getting-started/requirements.md)
