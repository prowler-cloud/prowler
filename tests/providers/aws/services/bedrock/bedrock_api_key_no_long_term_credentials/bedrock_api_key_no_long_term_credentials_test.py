from datetime import datetime, timedelta, timezone
from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_bedrock_api_key_no_long_term_credentials:
    @mock_aws
    def test_no_bedrock_api_keys(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials import (
                bedrock_api_key_no_long_term_credentials,
            )

            check = bedrock_api_key_no_long_term_credentials()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_bedrock_api_key_with_future_expiration_date(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user
        mock_user = User(
            name="test_user",
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user",
            attached_policies=[],
            inline_policies=[],
        )

        # Create a mock service-specific credential with future expiration date
        expiration_date = datetime.now(timezone.utc) + timedelta(days=30)
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=expiration_date,
            id="test-credential-id",
            service_name="bedrock.amazonaws.com",
            region=AWS_REGION_US_EAST_1,
        )

        iam.service_specific_credentials = [mock_credential]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials import (
                bedrock_api_key_no_long_term_credentials,
            )

            check = bedrock_api_key_no_long_term_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "will expire in" in result[0].status_extended
            assert "test-credential-id" in result[0].status_extended
            assert "test_user" in result[0].status_extended
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bedrock_api_key_with_critical_expiration_date(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user
        mock_user = User(
            name="test_user",
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user",
            attached_policies=[],
            inline_policies=[],
        )

        # Create a mock service-specific credential with very far future expiration date (>10000 days)
        expiration_date = datetime.now(timezone.utc) + timedelta(days=15000)
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=expiration_date,
            id="test-credential-id",
            service_name="bedrock.amazonaws.com",
            region=AWS_REGION_US_EAST_1,
        )

        iam.service_specific_credentials = [mock_credential]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials import (
                bedrock_api_key_no_long_term_credentials,
            )

            check = bedrock_api_key_no_long_term_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "never expires" in result[0].status_extended
            assert "test-credential-id" in result[0].status_extended
            assert "test_user" in result[0].status_extended
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert check.Severity == "critical"

    @mock_aws
    def test_bedrock_api_key_with_expired_date(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user
        mock_user = User(
            name="test_user",
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user",
            attached_policies=[],
            inline_policies=[],
        )

        # Create a mock service-specific credential with past expiration date
        expiration_date = datetime.now(timezone.utc) - timedelta(days=30)
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=expiration_date,
            id="test-credential-id",
            service_name="bedrock.amazonaws.com",
            region=AWS_REGION_US_EAST_1,
        )

        iam.service_specific_credentials = [mock_credential]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials import (
                bedrock_api_key_no_long_term_credentials,
            )

            check = bedrock_api_key_no_long_term_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has expired" in result[0].status_extended
            assert "test-credential-id" in result[0].status_extended
            assert "test_user" in result[0].status_extended
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bedrock_api_key_without_expiration_date_ignored(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user
        mock_user = User(
            name="test_user",
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user",
            attached_policies=[],
            inline_policies=[],
        )

        # Create a mock service-specific credential without expiration date (should be ignored)
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=None,  # No expiration date - should be ignored
            id="test-credential-id",
            service_name="bedrock.amazonaws.com",
            region=AWS_REGION_US_EAST_1,
        )

        iam.service_specific_credentials = [mock_credential]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials import (
                bedrock_api_key_no_long_term_credentials,
            )

            check = bedrock_api_key_no_long_term_credentials()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_non_bedrock_api_key_ignored(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user
        mock_user = User(
            name="test_user",
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user",
            attached_policies=[],
            inline_policies=[],
        )

        # Create a mock service-specific credential for a different service
        expiration_date = datetime.now(timezone.utc) + timedelta(days=30)
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=expiration_date,
            id="test-credential-id",
            service_name="codecommit.amazonaws.com",  # Different service
            region=AWS_REGION_US_EAST_1,
        )

        iam.service_specific_credentials = [mock_credential]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials import (
                bedrock_api_key_no_long_term_credentials,
            )

            check = bedrock_api_key_no_long_term_credentials()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_multiple_bedrock_api_keys_mixed_scenarios(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create mock users
        mock_user1 = User(
            name="test_user1",
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user1",
            attached_policies=[],
            inline_policies=[],
        )

        mock_user2 = User(
            name="test_user2",
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user2",
            attached_policies=[],
            inline_policies=[],
        )

        mock_user3 = User(
            name="test_user3",
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user3",
            attached_policies=[],
            inline_policies=[],
        )

        # Create a mock service-specific credential with future expiration date
        expiration_date1 = datetime.now(timezone.utc) + timedelta(days=30)
        mock_credential1 = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user1/credential/test-credential-id-1",
            user=mock_user1,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=expiration_date1,
            id="test-credential-id-1",
            service_name="bedrock.amazonaws.com",
            region=AWS_REGION_US_EAST_1,
        )

        # Create a mock service-specific credential with critical expiration date
        expiration_date2 = datetime.now(timezone.utc) + timedelta(days=15000)
        mock_credential2 = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user2/credential/test-credential-id-2",
            user=mock_user2,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=expiration_date2,
            id="test-credential-id-2",
            service_name="bedrock.amazonaws.com",
            region=AWS_REGION_US_EAST_1,
        )

        # Create a mock service-specific credential with expired date
        expiration_date3 = datetime.now(timezone.utc) - timedelta(days=30)
        mock_credential3 = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/test_user3/credential/test-credential-id-3",
            user=mock_user3,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=expiration_date3,
            id="test-credential-id-3",
            service_name="bedrock.amazonaws.com",
            region=AWS_REGION_US_EAST_1,
        )

        iam.service_specific_credentials = [
            mock_credential1,
            mock_credential2,
            mock_credential3,
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_long_term_credentials.bedrock_api_key_no_long_term_credentials import (
                bedrock_api_key_no_long_term_credentials,
            )

            check = bedrock_api_key_no_long_term_credentials()
            result = check.execute()

            assert len(result) == 3

            # Check the credential with future expiration date (FAIL)
            fail_result1 = next(
                r for r in result if r.resource_id == "test-credential-id-1"
            )
            assert fail_result1.status == "FAIL"
            assert "will expire in" in fail_result1.status_extended
            assert "test-credential-id-1" in fail_result1.status_extended
            assert "test_user1" in fail_result1.status_extended

            # Check the credential with critical expiration date (FAIL)
            fail_result2 = next(
                r for r in result if r.resource_id == "test-credential-id-2"
            )
            assert fail_result2.status == "FAIL"
            assert "never expires" in fail_result2.status_extended
            assert "test-credential-id-2" in fail_result2.status_extended
            assert "test_user2" in fail_result2.status_extended

            # Check the credential with expired date (PASS)
            pass_result = next(
                r for r in result if r.resource_id == "test-credential-id-3"
            )
            assert pass_result.status == "PASS"
            assert "has expired" in pass_result.status_extended
            assert "test-credential-id-3" in pass_result.status_extended
            assert "test_user3" in pass_result.status_extended
