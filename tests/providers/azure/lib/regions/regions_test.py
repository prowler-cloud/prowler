import pytest
from azure.identity import AzureAuthorityHosts

from prowler.providers.azure.lib.regions.regions import (
    AZURE_CHINA_CLOUD,
    AZURE_CHINA_GRAPH_HOST,
    AZURE_CHINA_GRAPH_SCOPE,
    AZURE_CHINA_LOGS_ENDPOINT,
    AZURE_GENERIC_CLOUD,
    AZURE_GENERIC_GRAPH_HOST,
    AZURE_GENERIC_GRAPH_SCOPE,
    AZURE_GENERIC_LOGS_ENDPOINT,
    AZURE_US_GOV_CLOUD,
    AZURE_US_GOV_GRAPH_HOST,
    AZURE_US_GOV_GRAPH_SCOPE,
    AZURE_US_GOV_LOGS_ENDPOINT,
    get_regions_config,
)


class Test_azure_regions:
    def test_get_regions_config(self):
        allowed_regions = [
            "AzureCloud",
            "AzureChinaCloud",
            "AzureUSGovernment",
        ]
        expected_output = {
            "AzureCloud": {
                "authority": None,
                "base_url": AZURE_GENERIC_CLOUD,
                "credential_scopes": [AZURE_GENERIC_CLOUD + "/.default"],
                "graph_host": AZURE_GENERIC_GRAPH_HOST,
                "graph_scope": AZURE_GENERIC_GRAPH_SCOPE,
                "logs_endpoint": AZURE_GENERIC_LOGS_ENDPOINT,
            },
            "AzureChinaCloud": {
                "authority": AzureAuthorityHosts.AZURE_CHINA,
                "base_url": AZURE_CHINA_CLOUD,
                "credential_scopes": [AZURE_CHINA_CLOUD + "/.default"],
                "graph_host": AZURE_CHINA_GRAPH_HOST,
                "graph_scope": AZURE_CHINA_GRAPH_SCOPE,
                "logs_endpoint": AZURE_CHINA_LOGS_ENDPOINT,
            },
            "AzureUSGovernment": {
                "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
                "base_url": AZURE_US_GOV_CLOUD,
                "credential_scopes": [AZURE_US_GOV_CLOUD + "/.default"],
                "graph_host": AZURE_US_GOV_GRAPH_HOST,
                "graph_scope": AZURE_US_GOV_GRAPH_SCOPE,
                "logs_endpoint": AZURE_US_GOV_LOGS_ENDPOINT,
            },
        }

        for region in allowed_regions:
            region_config = get_regions_config(region)
            assert region_config == expected_output[region]

    @pytest.mark.parametrize(
        "prefix,suffix",
        [
            ("", ""),
            ("https://", ""),
            ("https://", "/"),
            ("HTTPS://", ""),
            ("", "/"),
            (" https://", "/ "),
        ],
    )
    def test_get_regions_config_custom(self, prefix, suffix):
        region_endpoints = {
            "authority_host": f"{prefix}login.example.com{suffix}",
            "resource_manager": f"{prefix}management.example.com{suffix}",
            "graph": f"{prefix}graph.example.com:8443{suffix}",
            "logs": f"{prefix}api.loganalytics.example.com{suffix}",
        }
        assert get_regions_config("AzureCustom", region_endpoints) == {
            "authority": "login.example.com",
            "base_url": "https://management.example.com",
            "credential_scopes": ["https://management.example.com/.default"],
            "graph_host": "https://graph.example.com:8443",
            "graph_scope": "https://graph.example.com:8443/.default",
            "logs_endpoint": "https://api.loganalytics.example.com",
        }

    @pytest.mark.parametrize("logs", [None, "", " "])
    def test_get_regions_config_custom_without_logs(self, logs):
        region_endpoints = {
            "authority_host": "login.example.com",
            "resource_manager": "management.example.com",
            "graph": "graph.example.com",
            "logs": logs,
        }
        assert (
            get_regions_config("AzureCustom", region_endpoints)["logs_endpoint"] is None
        )

    @pytest.mark.parametrize(
        "region_endpoints,missing",
        [
            (None, "authority_host, resource_manager, graph"),
            (
                {"authority_host": "login.example.com", "graph": ""},
                "resource_manager, graph",
            ),
            (
                {
                    "authority_host": "login.example.com",
                    "resource_manager": "https://",
                    "graph": "/",
                },
                "resource_manager, graph",
            ),
            (
                {
                    "authority_host": "login.example.com",
                    "resource_manager": "management.example.com",
                    "graph": None,
                },
                "graph",
            ),
        ],
    )
    def test_get_regions_config_custom_missing_endpoints(
        self, region_endpoints, missing
    ):
        with pytest.raises(
            ValueError,
            match=f"Region AzureCustom requires these endpoints: {missing}$",
        ):
            get_regions_config("AzureCustom", region_endpoints)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://graph.example.com",
            "ftp://graph.example.com",
            "https://graph.example.com/v1.0",
            "graph.example.com/adfs",
            "graph.example.com//",
            "graph .example.com",
            "https://https://graph.example.com",
            "graph.example.com:port",
        ],
    )
    def test_get_regions_config_custom_rejects_invalid_endpoint(self, endpoint):
        with pytest.raises(ValueError) as exception:
            get_regions_config(
                "AzureCustom",
                {
                    "authority_host": "login.example.com",
                    "resource_manager": "management.example.com",
                    "graph": endpoint,
                },
            )

        assert (
            str(exception.value)
            == f"Region AzureCustom endpoint graph must be a host or an https:// URL: {endpoint}"
        )

    def test_get_regions_config_ignores_endpoints_for_built_in_region(self):
        assert get_regions_config(
            "AzureUSGovernment", {"resource_manager": "management.example.com"}
        ) == get_regions_config("AzureUSGovernment")
