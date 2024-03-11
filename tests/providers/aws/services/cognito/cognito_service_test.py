from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_Cognito_Service:
    # Test Cognito Service
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIDP(aws_provider)
        assert cognito.service == "cognito-idp"

    # Test Cognito client
    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIDP(aws_provider)
        for regional_client in cognito.regional_clients.values():
            assert regional_client.__class__.__name__ == "CognitoIdentityProvider"

    # Test Cognito session
    @mock_aws
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIDP(aws_provider)
        assert cognito.session.__class__.__name__ == "Session"

    # Test Cognito Session
    @mock_aws
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIDP(aws_provider)
        assert cognito.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_list_user_pools(self):
        user_pool_name_1 = "user_pool_test_1"
        user_pool_name_2 = "user_pool_test_2"
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito_client_eu_west_1 = client("cognito-idp", region_name="eu-west-1")
        cognito_client_us_east_1 = client("cognito-idp", region_name="us-east-1")
        cognito_client_eu_west_1.create_user_pool(PoolName=user_pool_name_1)
        cognito_client_us_east_1.create_user_pool(PoolName=user_pool_name_2)
        cognito = CognitoIDP(aws_provider)
        assert len(cognito.user_pools) == 2
        for user_pool in cognito.user_pools.values():
            assert (
                user_pool.name == user_pool_name_1 or user_pool.name == user_pool_name_2
            )
            assert user_pool.region == "eu-west-1" or user_pool.region == "us-east-1"

    @mock_aws
    def test_describe_user_pools(self):
        user_pool_name_1 = "user_pool_test_1"
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito_client_eu_west_1 = client("cognito-idp", region_name="eu-west-1")
        user_pool_id = cognito_client_eu_west_1.create_user_pool(
            PoolName=user_pool_name_1
        )["UserPool"]["Id"]
        cognito = CognitoIDP(aws_provider)
        assert len(cognito.user_pools) == 1
        for user_pool in cognito.user_pools.values():
            assert user_pool.name == user_pool_name_1
            assert user_pool.region == "eu-west-1"
            assert user_pool.id == user_pool_id
            assert user_pool.password_policy is not None
            assert user_pool.deletion_protection is not None
            assert user_pool.advanced_security_mode is not None
            assert user_pool.tags is not None

    @mock_aws
    def test_get_user_pool_mfa_config(self):
        user_pool_name_1 = "user_pool_test_1"
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito_client_eu_west_1 = client("cognito-idp", region_name="eu-west-1")
        user_pool_id = cognito_client_eu_west_1.create_user_pool(
            PoolName=user_pool_name_1
        )["UserPool"]["Id"]
        cognito_client_eu_west_1.set_user_pool_mfa_config(
            UserPoolId=user_pool_id,
            SoftwareTokenMfaConfiguration={"Enabled": True},
            MfaConfiguration="ON",
        )
        cognito = CognitoIDP(aws_provider)
        assert len(cognito.user_pools) == 1
        for user_pool in cognito.user_pools.values():
            assert user_pool.name == user_pool_name_1
            assert user_pool.region == "eu-west-1"
            assert user_pool.id == user_pool_id
            assert user_pool.mfa_config is not None
            assert user_pool.mfa_config.sms_authentication == {}
            assert user_pool.mfa_config.software_token_mfa_authentication == {
                "Enabled": True
            }
            assert user_pool.mfa_config.status == "ON"
