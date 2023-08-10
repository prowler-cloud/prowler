# Audit Info

In each Prowler provider we have a Python object called `audit_info` which is in charge of keeping the credentials, the configuration and the state of each audit, and it's passed to each service during the `__init__`.

- AWS: https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/lib/audit_info/models.py#L34-L54
- GCP: https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/lib/audit_info/models.py#L7-L30
- Azure: https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/lib/audit_info/models.py#L17-L31

This `audit_info` object is shared during the Prowler execution and for that reason is important to mock it in each test to isolate them. See the [testing guide](./unit-testing.md) for more information.
