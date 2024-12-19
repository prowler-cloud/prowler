# Microsoft365 authentication

By default Prowler uses MsGraph Python SDK identity package authentication methods using the class `ClientSecretCredential`.
This allows Prowler to authenticate against microsoft365 using the service principal authentication by environment variables (Enterprise Application)

To launch the tool first you need to set up the environment variables and then use:

```console
prowler microsoft365
```

To use Prowler you need to set up also the permissions required to access your resources in your Microsoft365 account, to more details refer to [Requirements](../../getting-started/requirements.md)
