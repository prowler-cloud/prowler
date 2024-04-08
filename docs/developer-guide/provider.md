# Providers

In each Prowler provider we have a Python object called `<provider_name>_provider` which is in charge of keeping the credentials, the configuration and the state of each audit, and it's passed to each service during the `__init__`. 

- AWS: https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_provider.py
- GCP: https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/gcp_provider.py
- Azure: https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/azure_provider.py

This `<provider_name>_provider` object is shared during the Prowler execution for each provider and for that reason is important to mock it in each test to isolate them. See the [testing guide](./unit-testing.md) for more information.
