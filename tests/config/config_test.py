import os
import pathlib
from unittest import mock

import pytest
from requests import Response

from prowler.config.config import (
    check_current_version,
    get_available_compliance_frameworks,
    load_and_validate_config_file,
    load_and_validate_fixer_config_file,
)
from prowler.providers.aws.aws_provider import get_aws_available_regions

MOCK_PROWLER_VERSION = "3.3.0"
MOCK_OLD_PROWLER_VERSION = "0.0.0"


def mock_prowler_get_latest_release(_, **kwargs):
    """Mock requests.get() to get the Prowler latest release"""
    response = Response()
    response._content = b'[{"name":"3.3.0"}]'
    return response


config_aws = {
    "shodan_api_key": None,
    "max_security_group_rules": 50,
    "max_ec2_instance_age_in_days": 180,
    "trusted_account_ids": [],
    "log_group_retention_days": 365,
    "max_idle_disconnect_timeout_in_seconds": 600,
    "max_disconnect_timeout_in_seconds": 300,
    "max_session_duration_seconds": 36000,
    "obsolete_lambda_runtimes": [
        "java8",
        "go1.x",
        "provided",
        "python3.6",
        "python2.7",
        "python3.7",
        "nodejs4.3",
        "nodejs4.3-edge",
        "nodejs6.10",
        "nodejs",
        "nodejs8.10",
        "nodejs10.x",
        "nodejs12.x",
        "nodejs14.x",
        "dotnet5.0",
        "dotnetcore1.0",
        "dotnetcore2.0",
        "dotnetcore2.1",
        "dotnetcore3.1",
        "ruby2.5",
        "ruby2.7",
    ],
    "organizations_enabled_regions": [],
    "organizations_trusted_delegated_administrators": [],
    "check_rds_instance_replicas": False,
    "ec2_allowed_interface_types": [
        "api_gateway_managed",
        "vpc_endpoint",
    ],
    "ec2_allowed_instance_owners": ["amazon-elb"],
}

config_azure = {"shodan_api_key": None}


class Test_Config:
    def test_get_aws_available_regions(self):
        assert len(get_aws_available_regions()) == 33

    @mock.patch(
        "prowler.config.config.requests.get", new=mock_prowler_get_latest_release
    )
    @mock.patch("prowler.config.config.prowler_version", new=MOCK_PROWLER_VERSION)
    def test_check_current_version_with_latest(self):
        assert (
            check_current_version()
            == f"Prowler {MOCK_PROWLER_VERSION} (You are running the latest version, yay!)"
        )

    @mock.patch(
        "prowler.config.config.requests.get", new=mock_prowler_get_latest_release
    )
    @mock.patch("prowler.config.config.prowler_version", new=MOCK_OLD_PROWLER_VERSION)
    def test_check_current_version_with_old(self):
        assert (
            check_current_version()
            == f"Prowler {MOCK_OLD_PROWLER_VERSION} (latest is {MOCK_PROWLER_VERSION}, upgrade for the latest features)"
        )

    def test_get_available_compliance_frameworks(self):
        compliance_frameworks = [
            "cisa_aws",
            "soc2_aws",
            "cis_1.4_aws",
            "cis_1.5_aws",
            "mitre_attack_aws",
            "gdpr_aws",
            "aws_foundational_security_best_practices_aws",
            "iso27001_2013_aws",
            "hipaa_aws",
            "cis_2.0_aws",
            "gxp_21_cfr_part_11_aws",
            "aws_well_architected_framework_security_pillar_aws",
            "gxp_eu_annex_11_aws",
            "nist_800_171_revision_2_aws",
            "nist_800_53_revision_4_aws",
            "nist_800_53_revision_5_aws",
            "ens_rd2022_aws",
            "nist_csf_1.1_aws",
            "aws_well_architected_framework_reliability_pillar_aws",
            "aws_audit_manager_control_tower_guardrails_aws",
            "rbi_cyber_security_framework_aws",
            "ffiec_aws",
            "pci_3.2.1_aws",
            "fedramp_moderate_revision_4_aws",
            "fedramp_low_revision_4_aws",
            "cis_2.0_gcp",
            "cis_1.8_kubernetes",
        ]
        assert (
            get_available_compliance_frameworks().sort() == compliance_frameworks.sort()
        )

    def test_load_and_validate_config_file_aws(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config.yaml"
        provider = "aws"

        assert load_and_validate_config_file(provider, config_test_file) == config_aws

    def test_load_and_validate_config_file_gcp(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config.yaml"
        provider = "gcp"

        assert load_and_validate_config_file(provider, config_test_file) is None

    def test_load_and_validate_config_file_kubernetes(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config.yaml"
        provider = "kubernetes"

        assert load_and_validate_config_file(provider, config_test_file) is None

    def test_load_and_validate_config_file_azure(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config.yaml"
        provider = "azure"

        assert load_and_validate_config_file(provider, config_test_file) == config_azure

    def test_load_and_validate_config_file_old_format(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config_old.yaml"

        assert load_and_validate_config_file("aws", config_test_file) == config_aws
        assert load_and_validate_config_file("gcp", config_test_file) == {}
        assert load_and_validate_config_file("azure", config_test_file) == {}
        assert load_and_validate_config_file("kubernetes", config_test_file) == {}

    def test_load_and_validate_config_file_invalid_config_file_path(self):
        provider = "aws"
        config_file_path = "invalid/path/to/fixer_config.yaml"

        with pytest.raises(SystemExit):
            load_and_validate_config_file(provider, config_file_path)

    def test_load_and_validate_fixer_config_aws(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/fixer_config.yaml"
        provider = "aws"

        assert load_and_validate_fixer_config_file(provider, config_test_file)

    def test_load_and_validate_fixer_config_gcp(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/fixer_config.yaml"
        provider = "gcp"

        assert load_and_validate_fixer_config_file(provider, config_test_file) == {}

    def test_load_and_validate_fixer_config_kubernetes(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/fixer_config.yaml"
        provider = "kubernetes"

        assert load_and_validate_fixer_config_file(provider, config_test_file) == {}

    def test_load_and_validate_fixer_config_azure(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/fixer_config.yaml"
        provider = "azure"

        assert load_and_validate_fixer_config_file(provider, config_test_file) == {}

    def test_load_and_validate_fixer_config_invalid_fixer_config_path(self):
        provider = "aws"
        fixer_config_path = "invalid/path/to/fixer_config.yaml"

        with pytest.raises(SystemExit):
            load_and_validate_fixer_config_file(provider, fixer_config_path)
