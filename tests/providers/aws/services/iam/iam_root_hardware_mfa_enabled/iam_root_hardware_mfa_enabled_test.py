from unittest import mock

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_iam_root_hardware_mfa_enabled_test:
    from tests.providers.aws.utils import (
        AWS_ACCOUNT_ARN,
        AWS_ACCOUNT_NUMBER,
        AWS_REGION_US_EAST_1,
        set_mocked_aws_provider,
    )

    def test_root_virtual_mfa_enabled(self):
        iam_client = mock.MagicMock
        iam_client.account_summary = {
            "SummaryMap": {"AccountMFAEnabled": 1},
        }
        iam_client.virtual_mfa_devices = [
            {
                "SerialNumber": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/mfa",
                "User": {"Arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
            }
        ]
        iam_client.audited_partition = "aws"
        iam_client.region = AWS_REGION_US_EAST_1
        iam_client.mfa_arn_template = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa"
        iam_client.organization_features = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=iam_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Root account has a virtual MFA instead of a hardware MFA device enabled."
            )
            assert result[0].resource_id == "<root_account>"
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa"

    def test_root_hardware_mfa_enabled(self):
        iam_client = mock.MagicMock
        iam_client.account_summary = {
            "SummaryMap": {"AccountMFAEnabled": 1},
        }
        iam_client.virtual_mfa_devices = []
        iam_client.audited_partition = "aws"
        iam_client.region = AWS_REGION_US_EAST_1
        iam_client.mfa_arn_template = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa"
        iam_client.organization_features = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=iam_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Root account has a hardware MFA device enabled."
            )
            assert result[0].resource_id == "<root_account>"
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa"

    def test_root_hardware_mfa_enabled_none_summary(self):
        iam_client = mock.MagicMock
        iam_client.account_summary = None
        iam_client.virtual_mfa_devices = []
        iam_client.audited_partition = "aws"
        iam_client.region = AWS_REGION_US_EAST_1
        iam_client.mfa_arn_template = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa"
        iam_client.organization_features = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=iam_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert len(result) == 0
