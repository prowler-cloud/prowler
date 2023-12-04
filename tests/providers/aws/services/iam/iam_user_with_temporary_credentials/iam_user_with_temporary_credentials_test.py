from unittest import mock

from prowler.providers.aws.services.iam.iam_service import IAM
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

IAM_USER_NAME = "test-user"
IAM_USER_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{IAM_USER_NAME}"
USER_DATA = (IAM_USER_NAME, IAM_USER_ARN)


class Test_iam_user_with_temporary_credentials:
    def test_no_users(self):
        iam_client = mock.MagicMock
        iam_client.region = AWS_REGION_EU_WEST_1

        iam_client.access_keys_metadata = {}
        iam_client.last_accessed_services = {}

        # Generate temporary credentials usage
        iam_client.user_temporary_credentials_usage = {}
        iam_client.__get_user_temporary_credentials_usage__ = (
            IAM.__get_user_temporary_credentials_usage__
        )
        iam_client.__get_user_temporary_credentials_usage__(iam_client)

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_service.IAM",
            new=iam_client,
        ) as iam_service, mock.patch(
            "prowler.providers.aws.services.iam.iam_client.iam_client",
            new=iam_service,
        ):
            from prowler.providers.aws.services.iam.iam_user_with_temporary_credentials.iam_user_with_temporary_credentials import (
                iam_user_with_temporary_credentials,
            )

            check = iam_user_with_temporary_credentials()
            result = check.execute()
            assert len(result) == 0

    def test_user_no_access_keys_no_accesed_services(self):
        iam_client = mock.MagicMock
        iam_client.region = AWS_REGION_EU_WEST_1

        iam_client.access_keys_metadata = {USER_DATA: []}
        iam_client.last_accessed_services = {USER_DATA: []}

        # Generate temporary credentials usage
        iam_client.user_temporary_credentials_usage = {}
        iam_client.__get_user_temporary_credentials_usage__ = (
            IAM.__get_user_temporary_credentials_usage__
        )
        iam_client.__get_user_temporary_credentials_usage__(iam_client)

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_service.IAM",
            new=iam_client,
        ) as iam_service, mock.patch(
            "prowler.providers.aws.services.iam.iam_client.iam_client",
            new=iam_service,
        ):
            from prowler.providers.aws.services.iam.iam_user_with_temporary_credentials.iam_user_with_temporary_credentials import (
                iam_user_with_temporary_credentials,
            )

            check = iam_user_with_temporary_credentials()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User {IAM_USER_NAME} doesn't have long lived credentials with access to other services than IAM or STS."
            )
            assert result[0].resource_id == IAM_USER_NAME
            assert result[0].resource_arn == IAM_USER_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_user_access_keys_no_accesed_services(self):
        iam_client = mock.MagicMock
        iam_client.region = AWS_REGION_EU_WEST_1

        iam_client.access_keys_metadata = {USER_DATA: [{"AccessKeyId": 1}]}
        iam_client.last_accessed_services = {USER_DATA: []}

        # Generate temporary credentials usage
        iam_client.user_temporary_credentials_usage = {}
        iam_client.__get_user_temporary_credentials_usage__ = (
            IAM.__get_user_temporary_credentials_usage__
        )
        iam_client.__get_user_temporary_credentials_usage__(iam_client)

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_service.IAM",
            new=iam_client,
        ) as iam_service, mock.patch(
            "prowler.providers.aws.services.iam.iam_client.iam_client",
            new=iam_service,
        ):
            from prowler.providers.aws.services.iam.iam_user_with_temporary_credentials.iam_user_with_temporary_credentials import (
                iam_user_with_temporary_credentials,
            )

            check = iam_user_with_temporary_credentials()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User {IAM_USER_NAME} doesn't have long lived credentials with access to other services than IAM or STS."
            )
            assert result[0].resource_id == IAM_USER_NAME
            assert result[0].resource_arn == IAM_USER_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_user_access_keys_accesed_services_sts(self):
        iam_client = mock.MagicMock
        iam_client.region = AWS_REGION_EU_WEST_1

        iam_client.access_keys_metadata = {USER_DATA: [{"AccessKeyId": 1}]}
        iam_client.last_accessed_services = {USER_DATA: [{"ServiceNamespace": "sts"}]}

        # Generate temporary credentials usage
        iam_client.user_temporary_credentials_usage = {}
        iam_client.__get_user_temporary_credentials_usage__ = (
            IAM.__get_user_temporary_credentials_usage__
        )
        iam_client.__get_user_temporary_credentials_usage__(iam_client)

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_service.IAM",
            new=iam_client,
        ) as iam_service, mock.patch(
            "prowler.providers.aws.services.iam.iam_client.iam_client",
            new=iam_service,
        ):
            from prowler.providers.aws.services.iam.iam_user_with_temporary_credentials.iam_user_with_temporary_credentials import (
                iam_user_with_temporary_credentials,
            )

            check = iam_user_with_temporary_credentials()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User {IAM_USER_NAME} doesn't have long lived credentials with access to other services than IAM or STS."
            )
            assert result[0].resource_id == IAM_USER_NAME
            assert result[0].resource_arn == IAM_USER_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_access_keys_with_iam_and_sts(self):
        iam_client = mock.MagicMock
        iam_client.region = AWS_REGION_EU_WEST_1

        iam_client.access_keys_metadata = {USER_DATA: [{"AccessKeyId": 1}]}
        iam_client.last_accessed_services = {
            USER_DATA: [{"ServiceNamespace": "sts"}, {"ServiceNamespace": "iam"}]
        }

        # Generate temporary credentials usage
        iam_client.user_temporary_credentials_usage = {}
        iam_client.__get_user_temporary_credentials_usage__ = (
            IAM.__get_user_temporary_credentials_usage__
        )
        iam_client.__get_user_temporary_credentials_usage__(iam_client)

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_service.IAM",
            new=iam_client,
        ) as iam_service, mock.patch(
            "prowler.providers.aws.services.iam.iam_client.iam_client",
            new=iam_service,
        ):
            from prowler.providers.aws.services.iam.iam_user_with_temporary_credentials.iam_user_with_temporary_credentials import (
                iam_user_with_temporary_credentials,
            )

            check = iam_user_with_temporary_credentials()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User {IAM_USER_NAME} doesn't have long lived credentials with access to other services than IAM or STS."
            )
            assert result[0].resource_id == IAM_USER_NAME
            assert result[0].resource_arn == IAM_USER_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_access_keys_with_iam_and_ec2(self):
        iam_client = mock.MagicMock
        iam_client.region = AWS_REGION_EU_WEST_1

        iam_client.access_keys_metadata = {USER_DATA: [{"AccessKeyId": 1}]}
        iam_client.last_accessed_services = {
            USER_DATA: [{"ServiceNamespace": "iam"}, {"ServiceNamespace": "ec2"}]
        }

        # Generate temporary credentials usage
        iam_client.user_temporary_credentials_usage = {}
        iam_client.__get_user_temporary_credentials_usage__ = (
            IAM.__get_user_temporary_credentials_usage__
        )
        iam_client.__get_user_temporary_credentials_usage__(iam_client)

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_service.IAM",
            new=iam_client,
        ) as iam_service, mock.patch(
            "prowler.providers.aws.services.iam.iam_client.iam_client",
            new=iam_service,
        ):
            from prowler.providers.aws.services.iam.iam_user_with_temporary_credentials.iam_user_with_temporary_credentials import (
                iam_user_with_temporary_credentials,
            )

            check = iam_user_with_temporary_credentials()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User {IAM_USER_NAME} has long lived credentials with access to other services than IAM or STS."
            )
            assert result[0].resource_id == IAM_USER_NAME
            assert result[0].resource_arn == IAM_USER_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
