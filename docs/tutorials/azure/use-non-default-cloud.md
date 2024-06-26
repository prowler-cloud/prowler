# Use non default Azure regions

Microsoft provides clouds for compliance with regional laws, which are available for your use.
By default, Prowler uses `AzureCloud` cloud which is the comercial one. (you can list all the available with `az cloud list --output table`).

At the time of writing this documentation the available Azure Clouds from different regions are the following:
- AzureCloud
- AzureChinaCloud
- AzureUSGovernment
- AzureGermanCloud

If you want to change the default one you must include the flag `--azure-region`, i.e.:

```console
prowler azure --az-cli-auth --azure-region AzureChinaCloud
```
