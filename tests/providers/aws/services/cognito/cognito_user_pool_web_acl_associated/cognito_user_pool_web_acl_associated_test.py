from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.cognito.cognito_service import UserPool
from prowler.providers.aws.services.wafv2.wafv2_service import WebAclv2
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_cognito_user_pool_web_acl_associated:
    def test_cognito_no_user_pools(self):
        cognito_client = mock.MagicMock
        cognito_client.user_pools = {}
        cognito_client.audited_account = AWS_ACCOUNT_NUMBER
        wafv2_client = mock.MagicMock
        wafv2_client.web_acls = []
        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            new=wafv2_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_client.wafv2_client",
            new=wafv2_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_web_acl_associated.cognito_user_pool_web_acl_associated import (
                cognito_user_pool_web_acl_associated,
            )

            check = cognito_user_pool_web_acl_associated()
            result = check.execute()

            assert len(result) == 0

    def test_cognito_no_web_acls(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                region=AWS_REGION_US_EAST_1,
                id=user_pool_id,
                arn=user_pool_arn,
                name=user_pool_name,
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        cognito_client.audited_account = AWS_ACCOUNT_NUMBER
        wafv2_client = mock.MagicMock
        wafv2_client.web_acls = []

        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            new=wafv2_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_client.wafv2_client",
            new=wafv2_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_web_acl_associated.cognito_user_pool_web_acl_associated import (
                cognito_user_pool_web_acl_associated,
            )

            check = cognito_user_pool_web_acl_associated()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Cognito User Pool is not associated with a Web ACL"
            )
            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn
            assert result[0].resource_name == user_pool_name

    def test_cognito_with_web_acls(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        user_pool_id = "eu-west-1_123456789"
        user_pool_name = "user_pool_name"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                region=AWS_REGION_US_EAST_1,
                id=user_pool_id,
                arn=user_pool_arn,
                name=user_pool_name,
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        cognito_client.audited_account = AWS_ACCOUNT_NUMBER
        wafv2_client = mock.MagicMock
        web_acl_arn = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/abcd1234"
        web_acl_name = "abcd1234"
        web_acl_id = "abcd1234"
        wafv2_client.web_acls = [
            WebAclv2(
                arn=web_acl_arn,
                name=web_acl_name,
                id=web_acl_id,
                albs=[],
                user_pools=["userpool/eu-west-1_123456789"],
                region="us-east-1",
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            new=wafv2_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_client.wafv2_client",
            new=wafv2_client,
        ):
            from prowler.providers.aws.services.cognito.cognito_user_pool_web_acl_associated.cognito_user_pool_web_acl_associated import (
                cognito_user_pool_web_acl_associated,
            )

            check = cognito_user_pool_web_acl_associated()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cognito User Pool is associated with the Web ACL {web_acl_name}"
            )
            assert result[0].resource_id == user_pool_id
            assert result[0].resource_arn == user_pool_arn
            assert result[0].resource_name == user_pool_name
