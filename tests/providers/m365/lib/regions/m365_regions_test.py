from azure.identity import AzureAuthorityHosts

from prowler.providers.m365.lib.regions.regions import (
    MICROSOFT365_CHINA_CLOUD,
    MICROSOFT365_GENERIC_CLOUD,
    MICROSOFT365_US_GOV_CLOUD,
    get_regions_config,
)


class Test_m365_regions:
    def test_get_regions_config(self):
        allowed_regions = [
            "M365Global",
            "M365China",
            "M365USGovernment",
        ]
        expected_output = {
            "M365Global": {
                "authority": None,
                "base_url": MICROSOFT365_GENERIC_CLOUD,
                "credential_scopes": [MICROSOFT365_GENERIC_CLOUD + "/.default"],
            },
            "M365China": {
                "authority": AzureAuthorityHosts.AZURE_CHINA,
                "base_url": MICROSOFT365_CHINA_CLOUD,
                "credential_scopes": [MICROSOFT365_CHINA_CLOUD + "/.default"],
            },
            "M365USGovernment": {
                "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
                "base_url": MICROSOFT365_US_GOV_CLOUD,
                "credential_scopes": [MICROSOFT365_US_GOV_CLOUD + "/.default"],
            },
        }

        for region in allowed_regions:
            region_config = get_regions_config(region)
            assert region_config == expected_output[region]
