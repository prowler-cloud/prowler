import argparse
from unittest.mock import MagicMock

import pytest

from prowler.providers.azure.lib.arguments import arguments

CUSTOM_ENDPOINT_ARGUMENTS = [
    "--azure-authority-host",
    "login.example.com",
    "--azure-resource-manager-endpoint",
    "https://management.example.com",
    "--azure-graph-endpoint",
    "https://graph.example.com",
]


def parse(command):
    parser = argparse.ArgumentParser()
    provider_parser = MagicMock()
    provider_parser.subparsers = parser.add_subparsers()
    provider_parser.common_providers_parser = argparse.ArgumentParser(add_help=False)
    arguments.init_parser(provider_parser)
    return parser.parse_args(["azure", "--sp-env-auth", *command])


class TestAzureCustomRegionArguments:
    def test_custom_region_with_its_endpoints_is_valid(self):
        args = parse(
            [
                "--azure-region",
                "AzureCustom",
                *CUSTOM_ENDPOINT_ARGUMENTS,
                "--azure-logs-endpoint",
                "https://api.loganalytics.example.com",
            ]
        )

        assert args.azure_authority_host == "login.example.com"
        assert args.azure_resource_manager_endpoint == "https://management.example.com"
        assert args.azure_graph_endpoint == "https://graph.example.com"
        assert args.azure_logs_endpoint == "https://api.loganalytics.example.com"
        assert arguments.validate_arguments(args) == (True, "")

    def test_custom_region_without_logs_endpoint_is_valid(self):
        args = parse(["--azure-region", "AzureCustom", *CUSTOM_ENDPOINT_ARGUMENTS])

        assert arguments.validate_arguments(args) == (True, "")

    def test_custom_region_requires_its_endpoints(self):
        args = parse(
            [
                "--azure-region",
                "AzureCustom",
                "--azure-authority-host",
                "login.example.com",
            ]
        )

        assert arguments.validate_arguments(args) == (
            False,
            "--azure-region AzureCustom requires --azure-resource-manager-endpoint, --azure-graph-endpoint",
        )

    @pytest.mark.parametrize("region", [None, "AzureUSGovernment"])
    def test_endpoints_need_the_custom_region(self, region):
        region_arguments = ["--azure-region", region] if region else []
        args = parse(
            [
                *region_arguments,
                "--azure-graph-endpoint",
                "https://graph.example.com",
                "--azure-logs-endpoint",
                "https://api.loganalytics.example.com",
            ]
        )

        assert arguments.validate_arguments(args) == (
            False,
            "--azure-graph-endpoint, --azure-logs-endpoint can only be used with --azure-region AzureCustom",
        )
