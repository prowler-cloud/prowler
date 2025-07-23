from datetime import timezone
from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

# Test policy documents
ADMIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}],
}

NON_ADMIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["bedrock:*"], "Resource": "*"}],
}

PRIVILEGE_ESCALATION_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateAccessKey",
                "iam:CreateUser",
                "iam:AttachUserPolicy",
            ],
            "Resource": "*",
        }
    ],
}


class Test_bedrock_api_key_no_administrative_privileges:
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
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges import (
                bedrock_api_key_no_administrative_privileges,
            )

            check = bedrock_api_key_no_administrative_privileges()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_bedrock_api_key_with_admin_attached_policy(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Create user
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name)["User"]["Arn"]

        # Create admin policy
        admin_policy_arn = iam_client.create_policy(
            PolicyName="AdminPolicy",
            PolicyDocument=dumps(ADMIN_POLICY),
            Path="/",
        )["Policy"]["Arn"]

        # Attach admin policy to user
        iam_client.attach_user_policy(UserName=user_name, PolicyArn=admin_policy_arn)

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from datetime import datetime

        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user with the attached policy
        mock_user = User(
            name=user_name,
            arn=user_arn,
            attached_policies=[
                {"PolicyArn": admin_policy_arn, "PolicyName": "AdminPolicy"}
            ],
            inline_policies=[],
        )

        # Create a mock service-specific credential
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{user_name}/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=None,
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
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges import (
                bedrock_api_key_no_administrative_privileges,
            )

            check = bedrock_api_key_no_administrative_privileges()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "API key test-credential-id in user test_user has administrative privileges through attached policy AdminPolicy."
            )
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bedrock_api_key_with_admin_inline_policy(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Create user
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name)["User"]["Arn"]

        # Create inline admin policy
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName="AdminInlinePolicy",
            PolicyDocument=dumps(ADMIN_POLICY),
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from datetime import datetime

        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user with the inline policy
        mock_user = User(
            name=user_name,
            arn=user_arn,
            attached_policies=[],
            inline_policies=["AdminInlinePolicy"],
        )

        # Create a mock service-specific credential
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{user_name}/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=None,
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
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges import (
                bedrock_api_key_no_administrative_privileges,
            )

            check = bedrock_api_key_no_administrative_privileges()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "API key test-credential-id in user test_user has administrative privileges through inline policy AdminInlinePolicy."
            )
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bedrock_api_key_with_privilege_escalation_attached_policy(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Create user
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name)["User"]["Arn"]

        # Create privilege escalation policy
        escalation_policy_arn = iam_client.create_policy(
            PolicyName="EscalationPolicy",
            PolicyDocument=dumps(PRIVILEGE_ESCALATION_POLICY),
            Path="/",
        )["Policy"]["Arn"]

        # Attach privilege escalation policy to user
        iam_client.attach_user_policy(
            UserName=user_name, PolicyArn=escalation_policy_arn
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from datetime import datetime

        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user with the attached policy
        mock_user = User(
            name=user_name,
            arn=user_arn,
            attached_policies=[
                {"PolicyArn": escalation_policy_arn, "PolicyName": "EscalationPolicy"}
            ],
            inline_policies=[],
        )

        # Create a mock service-specific credential
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{user_name}/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=None,
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
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges import (
                bedrock_api_key_no_administrative_privileges,
            )

            check = bedrock_api_key_no_administrative_privileges()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "API key test-credential-id in user test_user has privilege escalation through attached policy EscalationPolicy."
            )
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bedrock_api_key_with_privilege_escalation_inline_policy(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Create user
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name)["User"]["Arn"]

        # Create inline privilege escalation policy
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName="EscalationInlinePolicy",
            PolicyDocument=dumps(PRIVILEGE_ESCALATION_POLICY),
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from datetime import datetime

        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user with the inline policy
        mock_user = User(
            name=user_name,
            arn=user_arn,
            attached_policies=[],
            inline_policies=["EscalationInlinePolicy"],
        )

        # Create a mock service-specific credential
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{user_name}/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=None,
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
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges import (
                bedrock_api_key_no_administrative_privileges,
            )

            check = bedrock_api_key_no_administrative_privileges()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "API key test-credential-id in user test_user has privilege escalation through inline policy EscalationInlinePolicy."
            )
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bedrock_api_key_with_non_admin_policy(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Create user
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name)["User"]["Arn"]

        # Create non-admin policy
        non_admin_policy_arn = iam_client.create_policy(
            PolicyName="NonAdminPolicy",
            PolicyDocument=dumps(NON_ADMIN_POLICY),
            Path="/",
        )["Policy"]["Arn"]

        # Attach non-admin policy to user
        iam_client.attach_user_policy(
            UserName=user_name, PolicyArn=non_admin_policy_arn
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from datetime import datetime

        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user with the attached policy
        mock_user = User(
            name=user_name,
            arn=user_arn,
            attached_policies=[
                {"PolicyArn": non_admin_policy_arn, "PolicyName": "NonAdminPolicy"}
            ],
            inline_policies=[],
        )

        # Create a mock service-specific credential
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{user_name}/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=None,
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
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges import (
                bedrock_api_key_no_administrative_privileges,
            )

            check = bedrock_api_key_no_administrative_privileges()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "API key test-credential-id in user test_user has full service access through attached policy NonAdminPolicy."
            )
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bedrock_api_key_with_no_policies(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Create user
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from datetime import datetime

        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user with no policies
        mock_user = User(
            name=user_name,
            arn=user_arn,
            attached_policies=[],
            inline_policies=[],
        )

        # Create a mock service-specific credential
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{user_name}/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=None,
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
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges import (
                bedrock_api_key_no_administrative_privileges,
            )

            check = bedrock_api_key_no_administrative_privileges()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "API key test-credential-id in user test_user has no administrative privileges."
            )
            assert result[0].resource_id == "test-credential-id"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_non_bedrock_api_key_ignored(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Create user
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name)["User"]["Arn"]

        # Create admin policy
        admin_policy_arn = iam_client.create_policy(
            PolicyName="AdminPolicy",
            PolicyDocument=dumps(ADMIN_POLICY),
            Path="/",
        )["Policy"]["Arn"]

        # Attach admin policy to user
        iam_client.attach_user_policy(UserName=user_name, PolicyArn=admin_policy_arn)

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = IAM(aws_provider)

        # Mock service-specific credentials
        from datetime import datetime

        from prowler.providers.aws.services.iam.iam_service import (
            ServiceSpecificCredential,
            User,
        )

        # Create a mock user with the attached policy
        mock_user = User(
            name=user_name,
            arn=user_arn,
            attached_policies=[
                {"PolicyArn": admin_policy_arn, "PolicyName": "AdminPolicy"}
            ],
            inline_policies=[],
        )

        # Create a mock service-specific credential for a different service (not Bedrock)
        mock_credential = ServiceSpecificCredential(
            arn=f"arn:aws:iam:{AWS_REGION_US_EAST_1}:123456789012:user/{user_name}/credential/test-credential-id",
            user=mock_user,
            status="Active",
            create_date=datetime.now(timezone.utc),
            service_user_name=None,
            service_credential_alias=None,
            expiration_date=None,
            id="test-credential-id",
            service_name="codecommit.amazonaws.com",
            region=AWS_REGION_US_EAST_1,
        )

        iam.service_specific_credentials = [mock_credential]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges.iam_client",
                new=iam,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_api_key_no_administrative_privileges.bedrock_api_key_no_administrative_privileges import (
                bedrock_api_key_no_administrative_privileges,
            )

            check = bedrock_api_key_no_administrative_privileges()
            result = check.execute()

            # Should return 0 results since the API key is not for Bedrock
            assert len(result) == 0
