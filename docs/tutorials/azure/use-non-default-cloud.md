# Using Non-Default Azure Regions

Microsoft offers cloud environments that comply with regional regulations. These clouds are available for use based on your requirements. By default, Prowler utilizes the commercial `AzureCloud` environment. (To list all available Azure clouds, use `az cloud list --output table`).

As of this documentation's publication, the following Azure clouds are available:

- AzureCloud
- AzureChinaCloud
- AzureUSGovernmentL4
- AzureUSGovernmentL5

???+ note
    More information about Azure US Goverment region [here](https://devblogs.microsoft.com/microsoft365dev/new-microsoft-graph-endpoints-in-us-government-cloud/)

To change the default cloud, include the flag `--azure-region`. For example:

```console
prowler azure --az-cli-auth --azure-region AzureChinaCloud
```
