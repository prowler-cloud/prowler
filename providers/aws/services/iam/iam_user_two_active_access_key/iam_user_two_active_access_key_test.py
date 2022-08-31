from unittest import mock

from boto3 import client
from moto import mock_iam

from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.iam.iam_service import IAM


class Test_iam_user_two_active_access_key:
    @mock_iam
    def test_iam_user_two_active_access_key(self):
        # Create IAM Mocked Resources
        iam_client = client("iam")
        user = "test1"
        iam_client.create_user(UserName=user)
        # Create Access Key 1
        iam_client.create_access_key(UserName=user)
        # Create Access Key 2
        iam_client.create_access_key(UserName=user)

        with mock.patch(
            "providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    @mock_iam
    def test_iam_user_one_active_access_key(self):
        # Create IAM User
        iam_client = client("iam")
        user = "test1"
        iam_client.create_user(UserName=user)
        # Create Access Key 1
        iam_client.create_access_key(UserName=user)
        with mock.patch(
            "providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_iam
    def test_iam_user_without_active_access_key(self):
        # Create IAM User
        iam_client = client("iam")
        user = "test1"
        iam_client.create_user(UserName=user)
        with mock.patch(
            "providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_iam
    def test_iam_no_users(self):
        with mock.patch(
            "providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 0

    @mock_iam
    def test_bad_response(self):
        mock_client = mock.MagicMock()
        mock_client.credential_report = None
        with mock.patch(
            "providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key.iam_client",
            new=mock_client,
        ):
            # Test Check
            from providers.aws.services.iam.iam_user_two_active_access_key.iam_user_two_active_access_key import (
                iam_user_two_active_access_key,
            )

            check = iam_user_two_active_access_key()
            result = check.execute()

            assert len(result) == 0
