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
    "iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker"
)


class Test_iam_user_access_not_stale_to_sagemaker:
    @mock_aws
    def test_no_users_with_sagemaker_permissions(self):
        """No findings when no users have SageMaker in last accessed services."""
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            assert len(check.execute()) == 0

    @mock_aws
    def test_user_without_sagemaker_permissions(self):
        """User with non-SageMaker services is skipped."""
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            assert len(check.execute()) == 0

    @mock_aws
    def test_user_sagemaker_access_recent(self):
        """PASS when user accessed SageMaker within the threshold."""
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
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "accessed SageMaker" in result[0].status_extended
            assert IAM_USER_NAME in result[0].status_extended
            assert result[0].resource_id == IAM_USER_NAME
            assert result[0].resource_arn == IAM_USER_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_user_sagemaker_access_stale(self):
        """FAIL when user last accessed SageMaker more than 90 days ago."""
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

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=120)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has not accessed SageMaker" in result[0].status_extended
            assert "120 days" in result[0].status_extended
            assert IAM_USER_NAME in result[0].status_extended

    @mock_aws
    def test_user_sagemaker_never_accessed(self):
        """FAIL when user has SageMaker permissions but has never used them."""
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
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
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
        iam.audit_config = {"max_unused_sagemaker_access_days": 30}

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
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "45 days" in result[0].status_extended
            assert "threshold: 30 days" in result[0].status_extended

    @mock_aws
    def test_user_sagemaker_access_at_exact_threshold(self):
        """PASS when user accessed SageMaker exactly at the 90-day boundary."""
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
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "90 days ago" in result[0].status_extended
            assert "threshold: 90 days" in result[0].status_extended

    @mock_aws
    def test_user_sagemaker_access_one_day_over_threshold(self):
        """FAIL when user accessed SageMaker 91 days ago."""
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

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=91)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "91 days" in result[0].status_extended
            assert "threshold: 90 days" in result[0].status_extended

    @mock_aws
    def test_user_sagemaker_access_with_string_date(self):
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
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
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
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_tags == user_tags

    @mock_aws
    def test_multiple_users_mixed_results(self):
        """Multiple users: one recent (PASS), one stale (FAIL), one without SageMaker (skipped)."""
        from prowler.providers.aws.services.iam.iam_service import IAM, User

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        recent_user_name = "recent-user"
        recent_user_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{recent_user_name}"
        stale_user_name = "stale-user"
        stale_user_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{stale_user_name}"
        no_sagemaker_user_name = "no-sagemaker-user"
        no_sagemaker_user_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{no_sagemaker_user_name}"
        )

        iam.users = [
            User(
                name=recent_user_name,
                arn=recent_user_arn,
                attached_policies=[],
                inline_policies=[],
            ),
            User(
                name=stale_user_name,
                arn=stale_user_arn,
                attached_policies=[],
                inline_policies=[],
            ),
            User(
                name=no_sagemaker_user_name,
                arn=no_sagemaker_user_arn,
                attached_policies=[],
                inline_policies=[],
            ),
        ]

        recent_access = datetime.now(timezone.utc) - timedelta(days=10)
        stale_access = datetime.now(timezone.utc) - timedelta(days=120)
        iam.last_accessed_services = {
            (recent_user_name, recent_user_arn): [
                {
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
                    "LastAuthenticated": recent_access,
                },
            ],
            (stale_user_name, stale_user_arn): [
                {
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
                    "LastAuthenticated": stale_access,
                },
            ],
            (no_sagemaker_user_name, no_sagemaker_user_arn): [
                {"ServiceNamespace": "s3", "ServiceName": "S3"},
            ],
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            result = check.execute()

            assert len(result) == 2
            results_by_id = {r.resource_id: r for r in result}

            assert results_by_id[recent_user_name].status == "PASS"
            assert (
                "accessed SageMaker" in results_by_id[recent_user_name].status_extended
            )

            assert results_by_id[stale_user_name].status == "FAIL"
            assert (
                "has not accessed SageMaker"
                in results_by_id[stale_user_name].status_extended
            )
            assert "120 days" in results_by_id[stale_user_name].status_extended

            assert no_sagemaker_user_name not in results_by_id

    @mock_aws
    def test_user_arn_not_in_users_list(self):
        """No findings when last_accessed_services entries do not match any iam.users."""
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)
        iam.users = []

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=10)
        iam.last_accessed_services = {
            USER_DATA: [
                {
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
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
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            assert check.execute() == []

    @mock_aws
    def test_sagemaker_among_multiple_services(self):
        """SageMaker entry is correctly found when mixed with other services."""
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

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=15)
        iam.last_accessed_services = {
            USER_DATA: [
                {"ServiceNamespace": "iam", "ServiceName": "IAM"},
                {"ServiceNamespace": "s3", "ServiceName": "S3"},
                {
                    "ServiceNamespace": "sagemaker",
                    "ServiceName": "Amazon SageMaker",
                    "LastAuthenticated": last_authenticated,
                },
                {"ServiceNamespace": "ec2", "ServiceName": "EC2"},
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_user_access_not_stale_to_sagemaker.iam_user_access_not_stale_to_sagemaker import (
                iam_user_access_not_stale_to_sagemaker,
            )

            check = iam_user_access_not_stale_to_sagemaker()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "accessed SageMaker" in result[0].status_extended
            assert "15 days ago" in result[0].status_extended
