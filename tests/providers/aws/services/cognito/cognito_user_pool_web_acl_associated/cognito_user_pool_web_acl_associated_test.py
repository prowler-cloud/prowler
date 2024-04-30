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
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            wafv2_client,
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
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                region=AWS_REGION_US_EAST_1,
                id="eu-west-1_123456789",
                arn=user_pool_arn,
                name="eu-west-1_123456789",
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
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            wafv2_client,
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

    def test_cognito_with_web_acls(self):
        cognito_client = mock.MagicMock
        user_pool_arn = f"arn:aws:cognito-idp:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:userpool/eu-west-1_123456789"
        cognito_client.user_pools = {
            user_pool_arn: UserPool(
                region=AWS_REGION_US_EAST_1,
                id="eu-west-1_123456789",
                arn=user_pool_arn,
                name="eu-west-1_123456789",
                last_modified=datetime.now(),
                creation_date=datetime.now(),
                status="ACTIVE",
            )
        }
        cognito_client.audited_account = AWS_ACCOUNT_NUMBER
        wafv2_client = mock.MagicMock
        wafv2_client.web_acls = [
            WebAclv2(
                arn="arn:aws:wafv2:us-east-1:123456789012:regional/webacl/abcd1234",
                name="abcd1234",
                id="abcd1234",
                albs=[],
                user_pools=["userpool/eu-west-1_123456789"],
                region="us-east-1",
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.cognito.cognito_service.CognitoIDP",
            cognito_client,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.WAFv2",
            wafv2_client,
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
                == "Cognito User Pool is associated with the Web ACL abcd1234"
            )
            assert result[0].resource_id == "eu-west-1_123456789"
            assert result[0].resource_arn == user_pool_arn
