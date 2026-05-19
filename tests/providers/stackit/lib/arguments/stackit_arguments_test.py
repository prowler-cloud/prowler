import argparse

import pytest

from prowler.providers.stackit.lib.arguments.arguments import init_parser


@pytest.fixture
def parser():
    parser = argparse.ArgumentParser()
    parser.common_providers_parser = argparse.ArgumentParser(add_help=False)
    parser.subparsers = parser.add_subparsers(dest="provider")
    init_parser(parser)
    return parser


class TestStackITArguments:
    def test_project_id_argument_is_registered(self, parser):
        args = parser.parse_args(
            [
                "stackit",
                "--stackit-project-id",
                "12345678-1234-1234-1234-123456789abc",
            ]
        )

        assert args.stackit_project_id == "12345678-1234-1234-1234-123456789abc"

    def test_api_token_argument_is_not_registered(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["stackit", "--stackit-api-token", "secret-token"])

    def test_scan_unused_services_defaults_to_false(self, parser):
        args = parser.parse_args(["stackit"])
        assert args.scan_unused_services is False

    def test_scan_unused_services_flag_sets_true(self, parser):
        args = parser.parse_args(["stackit", "--scan-unused-services"])
        assert args.scan_unused_services is True
