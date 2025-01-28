from azure.identity import AzureAuthorityHosts

from prowler.providers.microsoft365.lib.regions.regions import (
    MICROSOFT365_CHINA_CLOUD,
    MICROSOFT365_GENERIC_CLOUD,
    MICROSOFT365_US_GOV_CLOUD,
    get_regions_config,
)


class Test_microsoft365_regions:
    def test_get_regions_config(self):
        allowed_regions = [
            "Microsoft365Global",
            "Microsoft365China",
            "Microsoft365USGovernment",
        ]
        expected_output = {
            "Microsoft365Global": {
                "authority": None,
                "base_url": MICROSOFT365_GENERIC_CLOUD,
                "credential_scopes": [MICROSOFT365_GENERIC_CLOUD + "/.default"],
            },
            "Microsoft365China": {
                "authority": AzureAuthorityHosts.AZURE_CHINA,
                "base_url": MICROSOFT365_CHINA_CLOUD,
                "credential_scopes": [MICROSOFT365_CHINA_CLOUD + "/.default"],
            },
            "Microsoft365USGovernment": {
                "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
                "base_url": MICROSOFT365_US_GOV_CLOUD,
                "credential_scopes": [MICROSOFT365_US_GOV_CLOUD + "/.default"],
            },
        }

        for region in allowed_regions:
            region_config = get_regions_config(region)
            assert region_config == expected_output[region]
