import re
from logging import WARNING

import botocore
import pytest
from boto3 import session
from botocore.client import ClientError
from mock import MagicMock, patch

from prowler.lib.outputs.asff.asff import ASFF
from prowler.providers.aws.lib.security_hub.exceptions.exceptions import (
    SecurityHubInvalidRegionError,
    SecurityHubNoEnabledRegionsError,
)
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHub
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_2,
)

# Mocking Security Hub Get Findings
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "BatchImportFindings":
        return {
            "FailedCount": 0,
            "SuccessCount": 1,
        }
    if operation_name == "DescribeHub":
        return {
            "HubArn": f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:hub/default",
            "SubscribedAt": "2023-02-07T09:45:43.742Z",
            "AutoEnableControls": True,
            "ControlFindingGenerator": "STANDARD_CONTROL",
        }

    if operation_name == "ListEnabledProductsForImport":
        return {
            "ProductSubscriptions": [
                f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:product-subscription/prowler/prowler",
                f"arn:aws:securityhub:{AWS_REGION_EU_WEST_2}:{AWS_ACCOUNT_NUMBER}:product-subscription/prowler/prowler",
            ]
        }

    return make_api_call(self, operation_name, kwarg)


class TestSecurityHub:

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_verify_security_hub_integration_enabled_per_region(self):
        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
        )
        assert security_hub._enabled_regions
        assert len(security_hub._enabled_regions) == 1
        assert AWS_REGION_EU_WEST_1 in security_hub._enabled_regions

    def test_verify_security_hub_integration_enabled_per_region_security_hub_disabled(
        self, caplog
    ):
        caplog.set_level(WARNING)

        with patch(
            "prowler.providers.aws.lib.security_hub.security_hub.Session.client",
        ) as mock_security_hub:
            error_message = f"Account {AWS_ACCOUNT_NUMBER} is not subscribed to AWS Security Hub in region {AWS_REGION_EU_WEST_1}"
            error_code = "InvalidAccessException"
            error_response = {
                "Error": {
                    "Code": error_code,
                    "Message": error_message,
                }
            }
            operation_name = "DescribeHub"
            mock_security_hub.side_effect = ClientError(error_response, operation_name)

            log_pattern = re.compile(
                r"ClientError -- \[\d+\]: An error occurred \({error_code}\) when calling the {operation_name} operation: {error_message}".format(
                    error_code=re.escape(error_code),
                    operation_name=re.escape(operation_name),
                    error_message=re.escape(error_message),
                )
            )

            security_hub = SecurityHub(
                aws_session=session.Session(
                    region_name=AWS_REGION_EU_WEST_1,
                ),
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            )

            assert security_hub._enabled_regions == {}

            assert any(
                log_pattern.match(record.message) for record in caplog.records
            ), "Expected log message not found"

    def test_verify_security_hub_integration_enabled_per_region_prowler_not_subscribed(
        self, caplog
    ):
        caplog.set_level(WARNING)

        with patch(
            "prowler.providers.aws.lib.security_hub.security_hub.Session.client",
        ) as mock_security_hub:
            mock_security_hub.describe_hub.return_value = None
            mock_security_hub.list_enabled_products_for_import.return_value = []

            security_hub = SecurityHub(
                aws_session=session.Session(
                    region_name=AWS_REGION_EU_WEST_1,
                ),
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            )

            assert security_hub._enabled_regions == {}
            assert caplog.record_tuples == [
                (
                    "root",
                    WARNING,
                    f"Security Hub is enabled in {AWS_REGION_EU_WEST_1} but Prowler integration does not accept findings. More info: https://docs.prowler.cloud/en/latest/tutorials/aws/securityhub/",
                )
            ]

    def test_verify_security_hub_integration_enabled_per_region_another_ClientError(
        self, caplog
    ):
        caplog.set_level(WARNING)

        with patch(
            "prowler.providers.aws.lib.security_hub.security_hub.Session.client",
        ) as mock_security_hub:
            error_message = f"Another exception in region {AWS_REGION_EU_WEST_1}"
            error_code = "AnotherException"
            error_response = {
                "Error": {
                    "Code": error_code,
                    "Message": error_message,
                }
            }
            operation_name = "DescribeHub"
            mock_security_hub.side_effect = ClientError(error_response, operation_name)

            log_pattern = re.compile(
                r"ClientError -- \[\d+\]: An error occurred \({error_code}\) when calling the {operation_name} operation: {error_message}".format(
                    error_code=re.escape(error_code),
                    operation_name=re.escape(operation_name),
                    error_message=re.escape(error_message),
                )
            )

            security_hub = SecurityHub(
                aws_session=session.Session(
                    region_name=AWS_REGION_EU_WEST_1,
                ),
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            )

            assert security_hub._enabled_regions == {}
            assert any(
                log_pattern.match(record.message) for record in caplog.records
            ), "Expected log message not found"

    def test_verify_security_hub_integration_enabled_per_region_another_Exception(
        self, caplog
    ):
        caplog.set_level(WARNING)

        with patch(
            "prowler.providers.aws.lib.security_hub.security_hub.Session.client",
        ) as mock_security_hub:
            error_message = f"Another exception in region {AWS_REGION_EU_WEST_1}"
            mock_security_hub.side_effect = Exception(error_message)

            security_hub = SecurityHub(
                aws_session=session.Session(
                    region_name=AWS_REGION_EU_WEST_1,
                ),
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            )

            log_pattern = re.compile(
                r"Exception -- \[\d+\]: {error_message}".format(
                    error_message=re.escape(error_message),
                )
            )

            assert security_hub._enabled_regions == {}
            assert any(
                log_pattern.match(record.message) for record in caplog.records
            ), "Expected log message not found"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_enabled_region_all_statuses(self):
        findings = [generate_finding_output(status="PASS", region=AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            findings=asff.data,
        )

        assert security_hub._findings_per_region == {
            AWS_REGION_EU_WEST_1: [asff.data[0]]
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_all_statuses_MANUAL_finding(self):
        findings = [
            generate_finding_output(status="MANUAL", region=AWS_REGION_EU_WEST_1)
        ]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            findings=asff.data,
        )

        assert security_hub._findings_per_region == {}

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_disabled_region(self):
        findings = [generate_finding_output(status="PASS", region=AWS_REGION_EU_WEST_2)]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            findings=asff.data,
        )

        assert security_hub._findings_per_region == {AWS_REGION_EU_WEST_1: []}

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_FAIL_and_FAIL_statuses(self):
        findings = [generate_finding_output(status="FAIL", region=AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            findings=asff.data,
        )

        assert security_hub._findings_per_region == {
            AWS_REGION_EU_WEST_1: [asff.data[0]]
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_send_sh_only_fails_PASS(self):
        findings = [generate_finding_output(status="PASS", region=AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            findings=asff.data,
            send_only_fails=True,
        )

        assert security_hub._findings_per_region == {AWS_REGION_EU_WEST_1: []}

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_send_sh_only_fails_FAIL(self):
        findings = [generate_finding_output(status="FAIL", region=AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            findings=asff.data,
            send_only_fails=True,
        )

        assert security_hub._findings_per_region == {
            AWS_REGION_EU_WEST_1: [asff.data[0]]
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_no_audited_regions(self):
        findings = [generate_finding_output(status="PASS", region=AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[],
            findings=asff.data,
            send_only_fails=True,
        )

        assert security_hub._findings_per_region == {}

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_muted_fail_with_send_sh_only_fails(
        self,
    ):
        findings = [
            generate_finding_output(
                status="FAIL", region=AWS_REGION_EU_WEST_1, muted=True
            )
        ]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            findings=asff.data,
            send_only_fails=True,
        )

        assert security_hub._findings_per_region == {
            AWS_REGION_EU_WEST_1: [],
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_filter_security_hub_findings_per_region_muted_fail_with_status_FAIL(self):
        findings = [
            generate_finding_output(
                status="FAIL", region=AWS_REGION_EU_WEST_1, muted=True
            )
        ]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            findings=asff.data,
            send_only_fails=True,
        )

        assert security_hub._findings_per_region == {
            AWS_REGION_EU_WEST_1: [],
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_batch_send_to_security_hub_one_finding(self):
        enabled_regions = [AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        findings = [
            generate_finding_output(status="PASS", region=AWS_REGION_EU_WEST_1),
            generate_finding_output(status="FAIL", region=AWS_REGION_EU_WEST_2),
        ]
        asff = ASFF(findings=findings)

        security_hub = SecurityHub(
            aws_session=session.Session(
                region_name=AWS_REGION_EU_WEST_1,
            ),
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_security_hub_available_regions=enabled_regions,
            findings=asff.data,
        )

        assert security_hub.batch_send_to_security_hub() == 2

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_security_hub_test_connection_success(self):

        # Test successful connection
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            regions={AWS_REGION_EU_WEST_1},
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None

    @patch("prowler.providers.aws.lib.security_hub.security_hub.Session.client")
    def test_security_hub_test_connection_invalid_access_exception(
        self, mock_security_hub_client
    ):
        # Mock an InvalidAccessException
        error_message = f"Account {AWS_ACCOUNT_NUMBER} is not subscribed to AWS Security Hub in region {AWS_REGION_EU_WEST_1}"
        error_code = "InvalidAccessException"
        error_response = {
            "Error": {
                "Code": error_code,
                "Message": error_message,
            }
        }
        operation_name = "DescribeHub"
        mock_security_hub_client.side_effect = ClientError(
            error_response, operation_name
        )

        # Test connection failure due to invalid access
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            regions={AWS_REGION_EU_WEST_1},
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, SecurityHubInvalidRegionError)

    @patch("prowler.providers.aws.lib.security_hub.security_hub.Session.client")
    def test_security_hub_test_connection_prowler_not_subscribed(
        self, mock_security_hub_client
    ):
        # Mock successful Security Hub but no Prowler subscription
        mock_security_hub_client.describe_hub.return_value = {}
        mock_security_hub_client.list_enabled_products_for_import.return_value = {
            "ProductSubscriptions": []
        }

        # Test connection failure due to missing Prowler subscription
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            regions={AWS_REGION_EU_WEST_1},
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, SecurityHubInvalidRegionError)

    @patch("prowler.providers.aws.lib.security_hub.security_hub.Session.client")
    def test_security_hub_test_connection_unexpected_exception(
        self, mock_security_hub_client
    ):
        # Mock unexpected exception
        mock_security_hub_client.side_effect = Exception("Unexpected error")

        # Test connection failure due to an unexpected exception
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            regions={AWS_REGION_EU_WEST_1},
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, SecurityHubInvalidRegionError)

    @patch("prowler.providers.aws.lib.security_hub.security_hub.Session.client")
    def test_security_hub_test_connection_no_regions_enabled(
        self, mock_security_hub_client
    ):
        # Mock unexpected exception
        mock_security_hub_client.side_effect = Exception("Unexpected error")

        # Test connection failure due to an unexpected exception
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, SecurityHubNoEnabledRegionsError)

    def test_init_without_session(self):
        with pytest.raises(ValueError) as e:
            SecurityHub(
                aws_session=None,
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
            )

        assert (
            str(e.value)
            == "If no role ARN is provided, a profile, an AWS access key ID, or an AWS secret access key is required."
        )

    def test_init_without_session_but_role_arn(self):
        with pytest.raises(ValueError) as e:
            SecurityHub(
                aws_session=None,
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
                role_arn="arn:aws:iam::123456789012:role/my-role",
            )

        assert (
            str(e.value)
            == "If a role ARN is provided, a session duration, an external ID, and a role session name are required."
        )

    def test_init_without_session_and_role_arn_but_session_duration(self):
        with pytest.raises(ValueError) as e:
            SecurityHub(
                aws_session=None,
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                aws_security_hub_available_regions=[AWS_REGION_EU_WEST_1],
                session_duration=3600,
            )

        assert (
            str(e.value)
            == "If no role ARN is provided, a profile, an AWS access key ID, or an AWS secret access key is required."
        )

    # Tests for new test_connection functionality - AWS Credential Management
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.get_available_aws_service_regions"
    )
    @patch(
        "prowler.providers.aws.lib.security_hub.security_hub.SecurityHub.verify_enabled_per_region"
    )
    def test_security_hub_test_connection_with_profile(
        self, mock_verify_enabled, mock_get_regions, mock_setup_session
    ):
        # Mock session setup
        mock_session = session.Session(region_name=AWS_REGION_EU_WEST_1)
        mock_setup_session.return_value = mock_session

        # Mock available regions
        mock_get_regions.return_value = [AWS_REGION_EU_WEST_1]

        # Mock enabled regions
        mock_verify_enabled.return_value = {AWS_REGION_EU_WEST_1: mock_session}

        # Test connection with profile
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            profile="test-profile",
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None
        mock_setup_session.assert_called_once_with(
            mfa=False,
            profile="test-profile",
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
        )

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.get_available_aws_service_regions"
    )
    @patch(
        "prowler.providers.aws.lib.security_hub.security_hub.SecurityHub.verify_enabled_per_region"
    )
    def test_security_hub_test_connection_with_access_keys(
        self, mock_verify_enabled, mock_get_regions, mock_setup_session
    ):
        # Mock session setup
        mock_session = session.Session(region_name=AWS_REGION_EU_WEST_1)
        mock_setup_session.return_value = mock_session

        # Mock available regions
        mock_get_regions.return_value = [AWS_REGION_EU_WEST_1]

        # Mock enabled regions
        mock_verify_enabled.return_value = {AWS_REGION_EU_WEST_1: mock_session}

        # Test connection with access keys
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_access_key_id="test-key",
            aws_secret_access_key="test-secret",
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None
        mock_setup_session.assert_called_once_with(
            mfa=False,
            profile=None,
            aws_access_key_id="test-key",
            aws_secret_access_key="test-secret",
            aws_session_token=None,
        )

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.get_available_aws_service_regions"
    )
    @patch(
        "prowler.providers.aws.lib.security_hub.security_hub.SecurityHub.verify_enabled_per_region"
    )
    def test_security_hub_test_connection_with_session_token(
        self, mock_verify_enabled, mock_get_regions, mock_setup_session
    ):
        # Mock session setup
        mock_session = session.Session(region_name=AWS_REGION_EU_WEST_1)
        mock_setup_session.return_value = mock_session

        # Mock available regions
        mock_get_regions.return_value = [AWS_REGION_EU_WEST_1]

        # Mock enabled regions
        mock_verify_enabled.return_value = {AWS_REGION_EU_WEST_1: mock_session}

        # Test connection with session token
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_session_token="test-token",
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None
        mock_setup_session.assert_called_once_with(
            mfa=False,
            profile=None,
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token="test-token",
        )

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.get_available_aws_service_regions"
    )
    @patch(
        "prowler.providers.aws.lib.security_hub.security_hub.SecurityHub.verify_enabled_per_region"
    )
    def test_security_hub_test_connection_with_mfa(
        self, mock_verify_enabled, mock_get_regions, mock_setup_session
    ):
        # Mock session setup
        mock_session = session.Session(region_name=AWS_REGION_EU_WEST_1)
        mock_setup_session.return_value = mock_session

        # Mock available regions
        mock_get_regions.return_value = [AWS_REGION_EU_WEST_1]

        # Mock enabled regions
        mock_verify_enabled.return_value = {AWS_REGION_EU_WEST_1: mock_session}

        # Test connection with MFA enabled
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            mfa_enabled=True,
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None
        mock_setup_session.assert_called_once_with(
            mfa=True,
            profile=None,
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
        )

    # Tests for Role Assumption functionality
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    @patch("prowler.providers.aws.aws_provider.AwsProvider.assume_role")
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.get_available_aws_service_regions"
    )
    @patch(
        "prowler.providers.aws.lib.security_hub.security_hub.SecurityHub.verify_enabled_per_region"
    )
    def test_security_hub_test_connection_with_role_arn(
        self,
        mock_verify_enabled,
        mock_get_regions,
        mock_assume_role,
        mock_setup_session,
    ):
        # Mock initial session setup
        mock_session = session.Session(region_name=AWS_REGION_EU_WEST_1)
        mock_setup_session.return_value = mock_session

        # Mock assumed role credentials
        from datetime import datetime, timezone

        from prowler.providers.aws.models import AWSCredentials

        mock_credentials = AWSCredentials(
            aws_access_key_id="assumed-key",
            aws_secret_access_key="assumed-secret",
            aws_session_token="assumed-token",
            expiration=datetime.now(timezone.utc),
        )
        mock_assume_role.return_value = mock_credentials

        # Mock available regions
        mock_get_regions.return_value = [AWS_REGION_EU_WEST_1]

        # Mock enabled regions
        mock_verify_enabled.return_value = {AWS_REGION_EU_WEST_1: mock_session}

        # Test connection with role ARN
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            role_arn="arn:aws:iam::123456789012:role/test-role",
            external_id="test-external-id",
            session_duration=7200,
            role_session_name="test-session",
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None
        mock_assume_role.assert_called_once()

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    @patch("prowler.providers.aws.aws_provider.AwsProvider.assume_role")
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.get_available_aws_service_regions"
    )
    @patch(
        "prowler.providers.aws.lib.security_hub.security_hub.SecurityHub.verify_enabled_per_region"
    )
    def test_security_hub_test_connection_with_role_arn_default_values(
        self,
        mock_verify_enabled,
        mock_get_regions,
        mock_assume_role,
        mock_setup_session,
    ):
        # Mock initial session setup
        mock_session = session.Session(region_name=AWS_REGION_EU_WEST_1)
        mock_setup_session.return_value = mock_session

        # Mock assumed role credentials
        from datetime import datetime, timezone

        from prowler.providers.aws.models import AWSCredentials

        mock_credentials = AWSCredentials(
            aws_access_key_id="assumed-key",
            aws_secret_access_key="assumed-secret",
            aws_session_token="assumed-token",
            expiration=datetime.now(timezone.utc),
        )
        mock_assume_role.return_value = mock_credentials

        # Mock available regions
        mock_get_regions.return_value = [AWS_REGION_EU_WEST_1]

        # Mock enabled regions
        mock_verify_enabled.return_value = {AWS_REGION_EU_WEST_1: mock_session}

        # Test connection with role ARN using default values
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            role_arn="arn:aws:iam::123456789012:role/test-role",
            external_id="test-external-id",
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None
        mock_assume_role.assert_called_once()

    # Tests for Error Handling - Session Setup Errors
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_setup_session_error(self, mock_setup_session):
        from prowler.providers.aws.exceptions.exceptions import AWSSetUpSessionError

        # Mock session setup error
        mock_setup_session.side_effect = AWSSetUpSessionError(
            file="test_file.py", original_exception=Exception("Session setup failed")
        )

        # Test connection failure due to session setup error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSSetUpSessionError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_setup_session_error_raise(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import AWSSetUpSessionError

        # Mock session setup error
        mock_setup_session.side_effect = AWSSetUpSessionError(
            file="test_file.py", original_exception=Exception("Session setup failed")
        )

        # Test that error is raised when raise_on_exception=True
        with pytest.raises(AWSSetUpSessionError):
            SecurityHub.test_connection(
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                raise_on_exception=True,
            )

    # Tests for Error Handling - Argument Validation Errors
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_argument_validation_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSArgumentTypeValidationError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSArgumentTypeValidationError(
            file="test_file.py", original_exception=ValueError("Invalid argument")
        )

        # Test connection failure due to argument validation error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSArgumentTypeValidationError)

    # Tests for Error Handling - Role ARN Validation Errors
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_role_arn_region_not_empty_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSIAMRoleARNRegionNotEmtpyError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSIAMRoleARNRegionNotEmtpyError(
            file="test_file.py"
        )

        # Test connection failure due to role ARN region validation error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSIAMRoleARNRegionNotEmtpyError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_role_arn_partition_empty_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSIAMRoleARNPartitionEmptyError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSIAMRoleARNPartitionEmptyError(
            file="test_file.py"
        )

        # Test connection failure due to role ARN partition validation error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSIAMRoleARNPartitionEmptyError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_role_arn_service_not_iam_sts_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSIAMRoleARNServiceNotIAMnorSTSError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSIAMRoleARNServiceNotIAMnorSTSError(
            file="test_file.py"
        )

        # Test connection failure due to role ARN service validation error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSIAMRoleARNServiceNotIAMnorSTSError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_role_arn_invalid_account_id_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSIAMRoleARNInvalidAccountIDError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSIAMRoleARNInvalidAccountIDError(
            file="test_file.py"
        )

        # Test connection failure due to role ARN account ID validation error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSIAMRoleARNInvalidAccountIDError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_role_arn_invalid_resource_type_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSIAMRoleARNInvalidResourceTypeError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSIAMRoleARNInvalidResourceTypeError(
            file="test_file.py"
        )

        # Test connection failure due to role ARN resource type validation error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSIAMRoleARNInvalidResourceTypeError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_role_arn_empty_resource_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSIAMRoleARNEmptyResourceError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSIAMRoleARNEmptyResourceError(
            file="test_file.py"
        )

        # Test connection failure due to role ARN empty resource validation error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSIAMRoleARNEmptyResourceError)

    # Tests for Error Handling - Role Assumption Errors
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_assume_role_error(self, mock_setup_session):
        from prowler.providers.aws.exceptions.exceptions import AWSAssumeRoleError

        # Mock session setup error
        mock_setup_session.side_effect = AWSAssumeRoleError(
            file="test_file.py", original_exception=Exception("Role assumption failed")
        )

        # Test connection failure due to role assumption error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSAssumeRoleError)

    # Tests for Error Handling - Profile and Credential Errors
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_profile_not_found_error(
        self, mock_setup_session
    ):
        from botocore.exceptions import ProfileNotFound

        # Mock session setup error
        mock_setup_session.side_effect = ProfileNotFound(profile="test-profile")

        # Test connection failure due to profile not found error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            profile="test-profile",
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, ProfileNotFound)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_profile_not_found_error_raise(
        self, mock_setup_session
    ):
        from botocore.exceptions import ProfileNotFound

        from prowler.providers.aws.exceptions.exceptions import AWSProfileNotFoundError

        # Mock session setup error
        mock_setup_session.side_effect = ProfileNotFound(profile="test-profile")

        # Test that error is raised when raise_on_exception=True
        with pytest.raises(AWSProfileNotFoundError):
            SecurityHub.test_connection(
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                profile="test-profile",
                raise_on_exception=True,
            )

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_no_credentials_error(
        self, mock_setup_session
    ):
        from botocore.exceptions import NoCredentialsError

        # Mock session setup error
        mock_setup_session.side_effect = NoCredentialsError()

        # Test connection failure due to no credentials error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, NoCredentialsError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_no_credentials_error_raise(
        self, mock_setup_session
    ):
        from botocore.exceptions import NoCredentialsError

        from prowler.providers.aws.exceptions.exceptions import AWSNoCredentialsError

        # Mock session setup error
        mock_setup_session.side_effect = NoCredentialsError()

        # Test that error is raised when raise_on_exception=True
        with pytest.raises(AWSNoCredentialsError):
            SecurityHub.test_connection(
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                raise_on_exception=True,
            )

    # Tests for Error Handling - Access Key and Secret Key Errors
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_access_key_id_invalid_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSAccessKeyIDInvalidError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSAccessKeyIDInvalidError(
            file="test_file.py", original_exception=ValueError("Invalid access key ID")
        )

        # Test connection failure due to invalid access key ID error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSAccessKeyIDInvalidError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_secret_access_key_invalid_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSSecretAccessKeyInvalidError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSSecretAccessKeyInvalidError(
            file="test_file.py",
            original_exception=ValueError("Invalid secret access key"),
        )

        # Test connection failure due to invalid secret access key error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSSecretAccessKeyInvalidError)

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_session_token_expired_error(
        self, mock_setup_session
    ):
        from prowler.providers.aws.exceptions.exceptions import (
            AWSSessionTokenExpiredError,
        )

        # Mock session setup error
        mock_setup_session.side_effect = AWSSessionTokenExpiredError(
            file="test_file.py", original_exception=ValueError("Session token expired")
        )

        # Test connection failure due to session token expired error
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, AWSSessionTokenExpiredError)

    # Tests for Error Handling - Generic Exception
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_generic_exception(self, mock_setup_session):
        # Mock session setup error
        mock_setup_session.side_effect = Exception("Generic error")

        # Test connection failure due to generic exception
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is False
        assert isinstance(connection.error, Exception)
        assert str(connection.error) == "Generic error"

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    def test_security_hub_test_connection_generic_exception_raise(
        self, mock_setup_session
    ):
        # Mock session setup error
        mock_setup_session.side_effect = Exception("Generic error")

        # Test that error is raised when raise_on_exception=True
        with pytest.raises(Exception) as exc_info:
            SecurityHub.test_connection(
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
                raise_on_exception=True,
            )

        assert str(exc_info.value) == "Generic error"

    # Tests for Edge Cases and Parameter Validation
    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.get_available_aws_service_regions"
    )
    @patch(
        "prowler.providers.aws.lib.security_hub.security_hub.SecurityHub.verify_enabled_per_region"
    )
    def test_security_hub_test_connection_with_aws_region(
        self, mock_verify_enabled, mock_get_regions, mock_setup_session
    ):
        # Mock session setup
        mock_session = session.Session(region_name=AWS_REGION_EU_WEST_1)
        mock_setup_session.return_value = mock_session

        # Mock available regions
        mock_get_regions.return_value = [AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]

        # Mock enabled regions
        mock_verify_enabled.return_value = {AWS_REGION_EU_WEST_1: mock_session}

        # Test connection with specific AWS region
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            aws_region=AWS_REGION_EU_WEST_1,
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None
        assert AWS_REGION_EU_WEST_1 in connection.enabled_regions
        assert AWS_REGION_EU_WEST_2 in connection.disabled_regions

    @patch("prowler.providers.aws.aws_provider.AwsProvider.setup_session")
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.get_available_aws_service_regions"
    )
    @patch(
        "prowler.providers.aws.lib.security_hub.security_hub.SecurityHub.verify_enabled_per_region"
    )
    def test_security_hub_test_connection_no_regions_specified(
        self, mock_verify_enabled, mock_get_regions, mock_setup_session
    ):
        # Mock session setup
        mock_session = session.Session(region_name=AWS_REGION_EU_WEST_1)
        mock_setup_session.return_value = mock_session

        # Mock available regions
        mock_get_regions.return_value = [AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]

        # Mock enabled regions
        mock_verify_enabled.return_value = {AWS_REGION_EU_WEST_1: mock_session}

        # Test connection without specifying regions
        connection = SecurityHub.test_connection(
            aws_account_id=AWS_ACCOUNT_NUMBER,
            aws_partition=AWS_COMMERCIAL_PARTITION,
            raise_on_exception=False,
        )

        assert connection.is_connected is True
        assert connection.error is None
        assert len(connection.enabled_regions) == 1
        assert len(connection.disabled_regions) == 1

    @patch("prowler.providers.aws.lib.security_hub.security_hub.AwsSetUpSession")
    def test_get_existing_findings_timestamps(self, mock_aws_setup):
        """Test that get_existing_findings_timestamps correctly retrieves existing findings timestamps."""
        # Mock findings per region
        mock_findings = [
            MagicMock(
                Id="prowler-test-check-123456789012-us-east-1-hash123",
                Region="us-east-1",
                Compliance=MagicMock(Status="FAILED"),
            ),
            MagicMock(
                Id="prowler-test-check-123456789012-us-west-2-hash456",
                Region="us-west-2",
                Compliance=MagicMock(Status="FAILED"),
            ),
        ]

        # Mock enabled regions
        mock_enabled_regions = {
            "us-east-1": MagicMock(),
            "us-west-2": MagicMock(),
        }

        # Mock paginator responses
        mock_page1 = {
            "Findings": [
                {
                    "Id": "prowler-test-check-123456789012-us-east-1-hash123",
                    "FirstObservedAt": "2023-01-01T00:00:00Z",
                    "CreatedAt": "2023-01-01T00:00:00Z",
                    "UpdatedAt": "2023-01-01T00:00:00Z",
                }
            ]
        }
        mock_page2 = {
            "Findings": [
                {
                    "Id": "prowler-test-check-123456789012-us-west-2-hash456",
                    "FirstObservedAt": "2023-01-15T00:00:00Z",
                    "CreatedAt": "2023-01-15T00:00:00Z",
                    "UpdatedAt": "2023-01-15T00:00:00Z",
                }
            ]
        }

        # Mock paginator
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [mock_page1, mock_page2]

        # Mock Security Hub client
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator

        # Create SecurityHub instance with mocked session
        mock_session = MagicMock()
        mock_aws_setup.return_value._session.current_session = mock_session

        security_hub = SecurityHub(
            aws_account_id="123456789012",
            aws_partition="aws",
            findings=mock_findings,
            aws_security_hub_available_regions=["us-east-1", "us-west-2"],
        )

        # Mock the enabled regions
        security_hub._enabled_regions = mock_enabled_regions
        security_hub._enabled_regions["us-east-1"] = mock_client
        security_hub._enabled_regions["us-west-2"] = mock_client

        # Mock findings per region
        security_hub._findings_per_region = {
            "us-east-1": [mock_findings[0]],
            "us-west-2": [mock_findings[1]],
        }

        # Call the method
        result = security_hub.get_existing_findings_timestamps()

        # Verify the result
        expected_result = {
            "prowler-test-check-123456789012-us-east-1-hash123": {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            },
            "prowler-test-check-123456789012-us-west-2-hash456": {
                "FirstObservedAt": "2023-01-15T00:00:00Z",
                "CreatedAt": "2023-01-15T00:00:00Z",
                "UpdatedAt": "2023-01-15T00:00:00Z",
            },
        }

        assert result == expected_result

        # Verify that the paginator was called correctly
        mock_client.get_paginator.assert_called_with("get_findings")
        assert mock_paginator.paginate.call_count == 2

    @patch("prowler.providers.aws.lib.security_hub.security_hub.AwsSetUpSession")
    def test_get_existing_findings_timestamps_empty_regions(self, mock_aws_setup):
        """Test that get_existing_findings_timestamps handles empty regions correctly."""
        # Mock session
        mock_session = MagicMock()
        mock_aws_setup.return_value._session.current_session = mock_session

        security_hub = SecurityHub(
            aws_account_id="123456789012",
            aws_partition="aws",
            findings=[],
            aws_security_hub_available_regions=[],
        )

        # Mock empty findings per region
        security_hub._findings_per_region = {}

        result = security_hub.get_existing_findings_timestamps()

        assert result == {}

    @patch("prowler.providers.aws.lib.security_hub.security_hub.AwsSetUpSession")
    def test_get_existing_findings_timestamps_with_error(self, mock_aws_setup):
        """Test that get_existing_findings_timestamps handles errors gracefully."""
        # Mock findings per region
        mock_findings = [
            MagicMock(
                Id="prowler-test-check-123456789012-us-east-1-hash123",
                Region="us-east-1",
                Compliance=MagicMock(Status="FAILED"),
            ),
        ]

        # Mock enabled regions
        mock_enabled_regions = {
            "us-east-1": MagicMock(),
        }

        # Mock client that raises an exception
        mock_client = MagicMock()
        mock_client.get_paginator.side_effect = Exception("Test error")

        # Mock session
        mock_session = MagicMock()
        mock_aws_setup.return_value._session.current_session = mock_session

        # Create SecurityHub instance
        security_hub = SecurityHub(
            aws_account_id="123456789012",
            aws_partition="aws",
            findings=mock_findings,
            aws_security_hub_available_regions=["us-east-1"],
        )

        # Mock the enabled regions
        security_hub._enabled_regions = mock_enabled_regions
        security_hub._enabled_regions["us-east-1"] = mock_client

        # Mock findings per region
        security_hub._findings_per_region = {
            "us-east-1": [mock_findings[0]],
        }

        # Call the method - should not raise exception
        result = security_hub.get_existing_findings_timestamps()

        # Should return empty dict due to error
        assert result == {}

    @patch("prowler.providers.aws.lib.security_hub.security_hub.AwsSetUpSession")
    def test_get_existing_findings_timestamps_partial_data(self, mock_aws_setup):
        """Test that get_existing_findings_timestamps handles partial timestamp data correctly."""
        # Mock findings per region
        mock_findings = [
            MagicMock(
                Id="prowler-test-check-123456789012-us-east-1-hash123",
                Region="us-east-1",
                Compliance=MagicMock(Status="FAILED"),
            ),
        ]

        # Mock enabled regions
        mock_enabled_regions = {
            "us-east-1": MagicMock(),
        }

        # Mock paginator responses with partial data
        mock_page = {
            "Findings": [
                {
                    "Id": "prowler-test-check-123456789012-us-east-1-hash123",
                    "FirstObservedAt": "2023-01-01T00:00:00Z",
                    # Missing CreatedAt and UpdatedAt
                }
            ]
        }

        # Mock paginator
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [mock_page]

        # Mock Security Hub client
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator

        # Mock session
        mock_session = MagicMock()
        mock_aws_setup.return_value._session.current_session = mock_session

        # Create SecurityHub instance
        security_hub = SecurityHub(
            aws_account_id="123456789012",
            aws_partition="aws",
            findings=mock_findings,
            aws_security_hub_available_regions=["us-east-1"],
        )

        # Mock the enabled regions
        security_hub._enabled_regions = mock_enabled_regions
        security_hub._enabled_regions["us-east-1"] = mock_client

        # Mock findings per region
        security_hub._findings_per_region = {
            "us-east-1": [mock_findings[0]],
        }

        # Call the method
        result = security_hub.get_existing_findings_timestamps()

        # Verify the result handles missing fields gracefully
        expected_result = {
            "prowler-test-check-123456789012-us-east-1-hash123": {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": None,
                "UpdatedAt": None,
            },
        }

        assert result == expected_result
