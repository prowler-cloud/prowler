from datetime import datetime, timedelta, timezone
from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

IAM_ROLE_NAME = "test-role"
IAM_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{IAM_ROLE_NAME}"
ROLE_DATA = (IAM_ROLE_NAME, IAM_ROLE_ARN)

CHECK_MODULE = (
    "prowler.providers.aws.services.iam."
    "iam_role_access_not_stale_to_bedrock.iam_role_access_not_stale_to_bedrock"
)


class Test_iam_role_access_not_stale_to_bedrock:
    @mock_aws
    def test_no_roles_with_bedrock_permissions(self):
        """No findings when no roles have Bedrock in last accessed services."""
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)
        iam.role_last_accessed_services = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=iam),
        ):
            from prowler.providers.aws.services.iam.iam_role_access_not_stale_to_bedrock.iam_role_access_not_stale_to_bedrock import (
                iam_role_access_not_stale_to_bedrock,
            )

            check = iam_role_access_not_stale_to_bedrock()
            assert len(check.execute()) == 0

    @mock_aws
    def test_role_bedrock_access_stale(self):
        """FAIL when a role last accessed Bedrock more than 60 days ago."""
        from prowler.providers.aws.services.iam.iam_service import IAM, Role

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_role = Role(
            name=IAM_ROLE_NAME,
            arn=IAM_ROLE_ARN,
            assume_role_policy={},
            is_service_role=False,
            attached_policies=[],
            inline_policies=[],
        )
        iam.roles = [mock_role]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=120)
        iam.role_last_accessed_services = {
            ROLE_DATA: [
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
            from prowler.providers.aws.services.iam.iam_role_access_not_stale_to_bedrock.iam_role_access_not_stale_to_bedrock import (
                iam_role_access_not_stale_to_bedrock,
            )

            check = iam_role_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has not accessed Bedrock" in result[0].status_extended
            assert "Role" in result[0].status_extended
            assert IAM_ROLE_NAME in result[0].status_extended
            assert result[0].resource_id == IAM_ROLE_NAME
            assert result[0].resource_arn == IAM_ROLE_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_role_bedrock_access_recent(self):
        """PASS when a role accessed Bedrock recently."""
        from prowler.providers.aws.services.iam.iam_service import IAM, Role

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_role = Role(
            name=IAM_ROLE_NAME,
            arn=IAM_ROLE_ARN,
            assume_role_policy={},
            is_service_role=False,
            attached_policies=[],
            inline_policies=[],
        )
        iam.roles = [mock_role]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=5)
        iam.role_last_accessed_services = {
            ROLE_DATA: [
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
            from prowler.providers.aws.services.iam.iam_role_access_not_stale_to_bedrock.iam_role_access_not_stale_to_bedrock import (
                iam_role_access_not_stale_to_bedrock,
            )

            check = iam_role_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "accessed Bedrock" in result[0].status_extended
            assert "Role" in result[0].status_extended
            assert IAM_ROLE_NAME in result[0].status_extended

    @mock_aws
    def test_role_bedrock_never_accessed(self):
        """FAIL when a role has Bedrock permissions but never accessed them."""
        from prowler.providers.aws.services.iam.iam_service import IAM, Role

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        mock_role = Role(
            name=IAM_ROLE_NAME,
            arn=IAM_ROLE_ARN,
            assume_role_policy={},
            is_service_role=False,
            attached_policies=[],
            inline_policies=[],
        )
        iam.roles = [mock_role]

        iam.role_last_accessed_services = {
            ROLE_DATA: [
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
            from prowler.providers.aws.services.iam.iam_role_access_not_stale_to_bedrock.iam_role_access_not_stale_to_bedrock import (
                iam_role_access_not_stale_to_bedrock,
            )

            check = iam_role_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has never used them" in result[0].status_extended
            assert "Role" in result[0].status_extended

    @mock_aws
    def test_role_tags_are_populated(self):
        """Verify resource_tags are populated from the role object."""
        from prowler.providers.aws.services.iam.iam_service import IAM, Role

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        role_tags = [{"Key": "Team", "Value": "ml-platform"}]
        mock_role = Role(
            name=IAM_ROLE_NAME,
            arn=IAM_ROLE_ARN,
            assume_role_policy={},
            is_service_role=False,
            attached_policies=[],
            inline_policies=[],
            tags=role_tags,
        )
        iam.roles = [mock_role]

        last_authenticated = datetime.now(timezone.utc) - timedelta(days=5)
        iam.role_last_accessed_services = {
            ROLE_DATA: [
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
            from prowler.providers.aws.services.iam.iam_role_access_not_stale_to_bedrock.iam_role_access_not_stale_to_bedrock import (
                iam_role_access_not_stale_to_bedrock,
            )

            check = iam_role_access_not_stale_to_bedrock()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_tags == role_tags
