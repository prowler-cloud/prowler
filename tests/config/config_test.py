from unittest import mock

from requests import Response

from prowler.config.config import (
    change_config_var,
    check_current_version,
    get_available_compliance_frameworks,
)
from prowler.providers.aws.aws_provider import get_aws_available_regions
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

MOCK_PROWLER_VERSION = "3.3.0"
MOCK_OLD_PROWLER_VERSION = "0.0.0"


def mock_prowler_get_latest_release(_):
    """Mock requests.get() to get the Prowler latest release"""
    response = Response()
    response._content = b'[{"name":"3.3.0"}]'
    return response


class Test_Config:
    def test_get_aws_available_regions(self):
        assert len(get_aws_available_regions()) == 32

    @mock.patch(
        "prowler.config.config.requests.get", new=mock_prowler_get_latest_release
    )
    @mock.patch("prowler.config.config.prowler_version", new=MOCK_PROWLER_VERSION)
    def test_check_current_version_with_latest(self):
        assert (
            check_current_version()
            == f"Prowler {MOCK_PROWLER_VERSION} (it is the latest version, yay!)"
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

    def test_change_config_var_aws(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=None,
            audited_account_arn=None,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=None,
            audit_config={"shodan_api_key": ""},
        )

        updated_audit_info = change_config_var("shodan_api_key", "XXXXXX", audit_info)
        assert audit_info == updated_audit_info
        assert audit_info.audit_config.get(
            "shodan_api_key"
        ) == updated_audit_info.audit_config.get("shodan_api_key")

    def test_change_config_var_aws_not_present(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=None,
            audited_account_arn=None,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=None,
            audit_config={},
        )

        updated_audit_info = change_config_var("not_found", "no_value", audit_info)
        assert audit_info == updated_audit_info
        assert updated_audit_info.audit_config.get("not_found") is None

    # Test load_and_validate_config_file

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
        ]
        assert get_available_compliance_frameworks() == compliance_frameworks
