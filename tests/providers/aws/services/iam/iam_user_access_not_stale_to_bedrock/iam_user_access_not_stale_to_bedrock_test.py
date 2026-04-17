from datetime import datetime, timedelta, timezone
from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

IAM_USER_NAME = "test-user"
IAM_USER_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{IAM_USER_NAME}"
USER_DATA = (IAM_USER_NAME, IAM_USER_ARN)

CHECK_MODULE = (
    "prowler.providers.aws.services.iam."
    "iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock"
)


class Test_iam_user_access_not_stale_to_bedrock:
    @mock_aws
    def test_no_users_with_bedrock_permissions(self):
        """No findings when no users have Bedrock in last accessed services."""
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)
        iam.last_accessed_services = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            assert len(check.execute()) == 0

    @mock_aws
    def test_user_without_bedrock_permissions(self):
        """User with non-Bedrock services is skipped."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
        )
        iam.users = [mock_user]
        iam.last_accessed_services = {
            USER_DATA: [
                {"ServiceNamespace": "iam", "ServiceName": "IAM"},
                {"ServiceNamespace": "s3", "ServiceName": "S3"},
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            assert len(check.execute()) == 0

    @mock_aws
    def test_user_bedrock_access_recent(self):
        """PASS when user accessed Bedrock within the threshold."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
        )
        iam.users = [mock_user]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=10)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "bedrock",
                    "ServiceName": "Amazon Bedrock",
                    "LastAuthenticated": last_authenticated,
                },
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "accessed Bedrock" in result[0].status_extended
            assert IAM_USER_NAME in result[0].status_extended
            assert result[0].resource_id == IAM_USER_NAME
            assert result[0].resource_arn == IAM_USER_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_user_bedrock_access_stale(self):
        """FAIL when user last accessed Bedrock more than 60 days ago."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
        )
        iam.users = [mock_user]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=90)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "bedrock",
                    "ServiceName": "Amazon Bedrock",
                    "LastAuthenticated": last_authenticated,
                },
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has not accessed Bedrock" in result[0].status_extended
            assert "90 days" in result[0].status_extended
            assert IAM_USER_NAME in result[0].status_extended

    @mock_aws
    def test_user_bedrock_never_accessed(self):
        """FAIL when user has Bedrock permissions but has never used them."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
        )
        iam.users = [mock_user]

        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "bedrock",
                    "ServiceName": "Amazon Bedrock",
                },
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has never used them" in result[0].status_extended

    @mock_aws
    def test_custom_threshold_via_audit_config(self):
        """Custom threshold from audit_config is respected."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)
        iam.audit_config = {"max_unused_bedrock_access_days": 30}

        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
        )
        iam.users = [mock_user]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=45)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "bedrock",
                    "ServiceName": "Amazon Bedrock",
                    "LastAuthenticated": last_authenticated,
                },
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "45 days" in result[0].status_extended
            assert "threshold: 30 days" in result[0].status_extended

    @mock_aws
    def test_user_bedrock_access_at_exact_threshold(self):
        """PASS when user accessed Bedrock exactly at the 60-day boundary."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
        )
        iam.users = [mock_user]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=60)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "bedrock",
                    "ServiceName": "Amazon Bedrock",
                    "LastAuthenticated": last_authenticated,
                },
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "60 days ago" in result[0].status_extended
            assert "threshold: 60 days" in result[0].status_extended

    @mock_aws
    def test_user_bedrock_access_one_day_over_threshold(self):
        """FAIL when user accessed Bedrock 61 days ago."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
        )
        iam.users = [mock_user]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=61)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "bedrock",
                    "ServiceName": "Amazon Bedrock",
                    "LastAuthenticated": last_authenticated,
                },
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "61 days" in result[0].status_extended
            assert "threshold: 60 days" in result[0].status_extended

    @mock_aws
    def test_user_bedrock_access_with_string_date(self):
        """PASS when LastAuthenticated is an ISO string instead of a datetime object."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
        )
        iam.users = [mock_user]

        last_access_date = datetime.now(timezone.utc) - timedelta(days=5)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "bedrock",
                    "ServiceName": "Amazon Bedrock",
                    "LastAuthenticated": last_access_date.isoformat(),
                },
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_aws
    def test_user_tags_are_populated(self):
        """Verify resource_tags are populated from the user object."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        user_tags = [{"Key": "Environment", "Value": "production"}]
        mock_user = User(
            name=IAM_USER_NAME,
            arn=IAM_USER_ARN,
            attached_policies=[],
            inline_policies=[],
            tags=user_tags,
        )
        iam.users = [mock_user]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=10)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "bedrock",
                    "ServiceName": "Amazon Bedrock",
                    "LastAuthenticated": last_authenticated,
                },
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_bedrock.iam_user_access_not_stale_to_bedrock import (
                iam_user_access_not_stale_to_bedrock,
            )

            check = iam_user_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_tags == user_tags
