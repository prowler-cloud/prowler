from unittest import mock

from moto import mock_aws

from prowler.providers.aws.services.macie.macie_service import Session
from prowler.providers.aws.services.s3.s3_service import Bucket
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_macie_is_enabled:
    @mock_aws
    def test_macie_disabled(self):
        s3_client = mock.MagicMock
        s3_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        s3_client.buckets = {}
        s3_client.regions_with_buckets = []

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
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.macie_client",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.s3_client",
            new=s3_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Macie is not enabled."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:macie:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:session"
            )

    @mock_aws
    def test_macie_enabled(self):
        s3_client = mock.MagicMock
        s3_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        s3_client.buckets = {}
        s3_client.regions_with_buckets = []

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
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.macie_client",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.s3_client",
            new=s3_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Macie is enabled."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:macie:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:session"
            )

    @mock_aws
    def test_macie_suspended_ignored(self):
        s3_client = mock.MagicMock
        s3_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        s3_client.buckets = {}
        s3_client.regions_with_buckets = []

        macie_client = mock.MagicMock
        macie_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.audited_partition = "aws"
        macie_client.region = AWS_REGION_EU_WEST_1
        macie_client.session_arn_template = f"arn:{macie_client.audited_partition}:macie:{macie_client.region}:{macie_client.audited_account}:session"
        macie_client._get_session_arn_template = mock.MagicMock(
            return_value=macie_client.session_arn_template
        )
        macie_client.sessions = [
            Session(
                status="PAUSED",
                region="eu-west-1",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        macie_client.provider._scan_unused_services = False

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.macie_client",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.s3_client",
            new=s3_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_macie_suspended_ignored_with_buckets(self):
        s3_client = mock.MagicMock
        s3_client.regions_with_buckets = [AWS_REGION_EU_WEST_1]
        s3_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        s3_client.buckets = [
            Bucket(
                name="test",
                arn="test-arn",
                region=AWS_REGION_EU_WEST_1,
            )
        ]

        macie_client = mock.MagicMock
        macie_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.audited_partition = "aws"
        macie_client.region = AWS_REGION_EU_WEST_1
        macie_client.sessions = [
            Session(
                status="PAUSED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        macie_client.session_arn_template = f"arn:{macie_client.audited_partition}:macie:{macie_client.region}:{macie_client.audited_account}:session"
        macie_client._get_session_arn_template = mock.MagicMock(
            return_value=macie_client.session_arn_template
        )
        macie_client.provider._scan_unused_services = False
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.macie_client",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.s3_client",
            new=s3_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "Macie is currently in a SUSPENDED state."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:macie:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:session"
            )

    @mock_aws
    def test_macie_suspended(self):
        s3_client = mock.MagicMock
        s3_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        macie_client = mock.MagicMock
        macie_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.audited_partition = "aws"
        macie_client.region = AWS_REGION_EU_WEST_1
        macie_client.sessions = [
            Session(
                status="PAUSED",
                region="eu-west-1",
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        macie_client.session_arn_template = f"arn:{macie_client.audited_partition}:macie:{macie_client.region}:{macie_client.audited_account}:session"
        macie_client._get_session_arn_template = mock.MagicMock(
            return_value=macie_client.session_arn_template
        )
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.macie_client",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled.s3_client",
            new=s3_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "Macie is currently in a SUSPENDED state."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:macie:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:session"
            )
