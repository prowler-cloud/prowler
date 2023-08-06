from unittest import mock

from requests import Response

from prowler.config.config import change_config_var, check_current_version
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
