from unittest import mock

from moto import mock_aws

from prowler.providers.aws.services.macie.macie_service import Session
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_macie_automated_sensitive_data_discovery_enabled:
    @mock_aws
    def test_macie_disabled(self):

        macie_client = mock.MagicMock
        macie_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.audited_partition = "aws"
        macie_client.region = AWS_REGION_EU_WEST_1
        macie_client.sessions = [
            Session(
                status="DISABLED",
                region="eu-west-1",
                automated_discovery_status="DISABLED",
            )
        ]
        macie_client.session_arn_template = f"arn:{macie_client.audited_partition}:macie:{macie_client.region}:{macie_client.audited_account}:session"
        macie_client._get_session_arn_template = mock.MagicMock(
            return_value=macie_client.session_arn_template
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_automated_sensitive_data_discovery_enabled.macie_automated_sensitive_data_discovery_enabled.macie_client",
            new=macie_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_automated_sensitive_data_discovery_enabled.macie_automated_sensitive_data_discovery_enabled import (
                macie_automated_sensitive_data_discovery_enabled,
            )

            check = macie_automated_sensitive_data_discovery_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_macie_enabled_automated_discovery_disabled(self):

        macie_client = mock.MagicMock
        macie_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.audited_partition = "aws"
        macie_client.region = AWS_REGION_EU_WEST_1
        macie_client.sessions = [
            Session(
                status="ENABLED",
                region="eu-west-1",
                automated_discovery_status="DISABLED",
            )
        ]
        macie_client.session_arn_template = f"arn:{macie_client.audited_partition}:macie:{macie_client.region}:{macie_client.audited_account}:session"
        macie_client._get_session_arn_template = mock.MagicMock(
            return_value=macie_client.session_arn_template
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_automated_sensitive_data_discovery_enabled.macie_automated_sensitive_data_discovery_enabled.macie_client",
            new=macie_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_automated_sensitive_data_discovery_enabled.macie_automated_sensitive_data_discovery_enabled import (
                macie_automated_sensitive_data_discovery_enabled,
            )

            check = macie_automated_sensitive_data_discovery_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Macie is enabled but it does not have automated sensitive data discovery."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:macie:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:session"
            )

    @mock_aws
    def test_macie_enabled_automated_discovery_enabled(self):

        macie_client = mock.MagicMock
        macie_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.audited_partition = "aws"
        macie_client.region = AWS_REGION_EU_WEST_1
        macie_client.sessions = [
            Session(
                status="ENABLED",
                region="eu-west-1",
                automated_discovery_status="ENABLED",
            )
        ]
        macie_client.session_arn_template = f"arn:{macie_client.audited_partition}:macie:{macie_client.region}:{macie_client.audited_account}:session"
        macie_client._get_session_arn_template = mock.MagicMock(
            return_value=macie_client.session_arn_template
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_automated_sensitive_data_discovery_enabled.macie_automated_sensitive_data_discovery_enabled.macie_client",
            new=macie_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_automated_sensitive_data_discovery_enabled.macie_automated_sensitive_data_discovery_enabled import (
                macie_automated_sensitive_data_discovery_enabled,
            )

            check = macie_automated_sensitive_data_discovery_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Macie has automated sensitive data discovery enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:macie:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:session"
            )
