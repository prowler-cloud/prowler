import pytest
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
                "powershell": {
                    "exchange_environment": None,
                    "exchange_scope": "https://outlook.office365.com/.default",
                    "teams_environment": None,
                },
            },
            "M365China": {
                "authority": AzureAuthorityHosts.AZURE_CHINA,
                "base_url": MICROSOFT365_CHINA_CLOUD,
                "credential_scopes": [MICROSOFT365_CHINA_CLOUD + "/.default"],
                "powershell": {
                    "exchange_environment": "O365China",
                    "exchange_scope": "https://partner.outlook.cn/.default",
                    "teams_environment": "TeamsChina",
                },
            },
            "M365USGovernment": {
                "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
                "base_url": MICROSOFT365_US_GOV_CLOUD,
                "credential_scopes": [MICROSOFT365_US_GOV_CLOUD + "/.default"],
                "powershell": {
                    "exchange_environment": "O365USGovGCCHigh",
                    "exchange_scope": "https://outlook.office365.us/.default",
                    "teams_environment": "TeamsGCCH",
                },
            },
        }

        for region in allowed_regions:
            region_config = get_regions_config(region)
            assert region_config == expected_output[region]

    @pytest.mark.parametrize(
        "authority_host, graph",
        [
            ("login.custom.cloud", "graph.custom.cloud"),
            ("https://login.custom.cloud", "https://graph.custom.cloud"),
            ("https://login.custom.cloud/", "https://graph.custom.cloud/"),
            (" login.custom.cloud ", " https://graph.custom.cloud "),
            ("HTTPS://login.custom.cloud", "Https://graph.custom.cloud/"),
        ],
    )
    def test_get_regions_config_custom(self, authority_host, graph):
        region_config = get_regions_config(
            "M365Custom", {"authority_host": authority_host, "graph": graph}
        )

        assert region_config == {
            "authority": "login.custom.cloud",
            "base_url": "https://graph.custom.cloud",
            "credential_scopes": ["https://graph.custom.cloud/.default"],
        }

    def test_get_regions_config_custom_with_port(self):
        region_config = get_regions_config(
            "M365Custom",
            {
                "authority_host": "login.custom.cloud:8443",
                "graph": "https://graph.custom.cloud:8443/",
            },
        )

        assert region_config == {
            "authority": "login.custom.cloud:8443",
            "base_url": "https://graph.custom.cloud:8443",
            "credential_scopes": ["https://graph.custom.cloud:8443/.default"],
        }

    @pytest.mark.parametrize(
        "region_endpoints, missing_endpoints",
        [
            (None, "authority_host, graph"),
            ({}, "authority_host, graph"),
            ({"authority_host": "login.custom.cloud"}, "graph"),
            ({"authority_host": None, "graph": "graph.custom.cloud"}, "authority_host"),
            ({"authority_host": "login.custom.cloud", "graph": ""}, "graph"),
        ],
    )
    def test_get_regions_config_custom_missing_endpoints(
        self, region_endpoints, missing_endpoints
    ):
        with pytest.raises(ValueError) as exception:
            get_regions_config("M365Custom", region_endpoints)

        assert (
            str(exception.value)
            == f"Region M365Custom requires these endpoints: {missing_endpoints}"
        )

    @pytest.mark.parametrize(
        "graph",
        [
            "http://graph.custom.cloud",
            "ftp://graph.custom.cloud",
            "https://graph.custom.cloud/v1.0",
            "graph.custom.cloud/v1.0",
            "https://graph.custom.cloud//",
            "graph.custom .cloud",
            "https://",
            "graph.custom.cloud:port",
        ],
    )
    def test_get_regions_config_custom_rejects_invalid_endpoints(self, graph):
        with pytest.raises(ValueError) as exception:
            get_regions_config(
                "M365Custom", {"authority_host": "login.custom.cloud", "graph": graph}
            )

        assert (
            str(exception.value)
            == f"Region M365Custom endpoint graph must be a host or an https:// URL: {graph}"
        )

    def test_get_regions_config_ignores_endpoints_for_built_in_regions(self):
        assert get_regions_config(
            "M365USGovernment",
            {"authority_host": "login.custom.cloud", "graph": "graph.custom.cloud"},
        ) == get_regions_config("M365USGovernment")
