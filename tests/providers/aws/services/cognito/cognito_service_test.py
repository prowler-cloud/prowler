from boto3 import client, session
from moto import mock_cognitoidp

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.cognito.cognito_service import Cognito
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_Cognito_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-1", "us-east-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test Cognito Service
    @mock_cognitoidp
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        cognito = Cognito(audit_info)
        assert cognito.service == "cognito-idp"

    # Test Cognito client
    @mock_cognitoidp
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        cognito = Cognito(audit_info)
        for regional_client in cognito.regional_clients.values():
            assert regional_client.__class__.__name__ == "CognitoIdentityProvider"

    # Test Cognito session
    @mock_cognitoidp
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        cognito = Cognito(audit_info)
        assert cognito.session.__class__.__name__ == "Session"

    # Test Cognito Session
    @mock_cognitoidp
    def test_audited_account(self):
        audit_info = self.set_mocked_audit_info()
        cognito = Cognito(audit_info)
        assert cognito.audited_account == AWS_ACCOUNT_NUMBER

    @mock_cognitoidp
    def test_list_user_pools(self):
        user_pool_name_1 = "user_pool_test_1"
        user_pool_name_2 = "user_pool_test_2"
        audit_info = self.set_mocked_audit_info()
        cognito_client_eu_west_1 = client("cognito-idp", region_name="eu-west-1")
        cognito_client_us_east_1 = client("cognito-idp", region_name="us-east-1")
        cognito_client_eu_west_1.create_user_pool(PoolName=user_pool_name_1)
        cognito_client_us_east_1.create_user_pool(PoolName=user_pool_name_2)
        cognito = Cognito(audit_info)
        assert len(cognito.user_pools) == 2
        for user_pool in cognito.user_pools:
            assert (
                user_pool.name == user_pool_name_1 or user_pool.name == user_pool_name_2
            )
            assert user_pool.region == "eu-west-1" or user_pool.region == "us-east-1"

    @mock_cognitoidp
    def test_describe_user_pools(self):
        user_pool_name_1 = "user_pool_test_1"
        audit_info = self.set_mocked_audit_info()
        cognito_client_eu_west_1 = client("cognito-idp", region_name="eu-west-1")
        user_pool_id = cognito_client_eu_west_1.create_user_pool(
            PoolName=user_pool_name_1
        )["UserPool"]["Id"]
        cognito = Cognito(audit_info)
        assert len(cognito.user_pools) == 1
        for user_pool in cognito.user_pools:
            assert user_pool.name == user_pool_name_1
            assert user_pool.region == "eu-west-1"
            assert user_pool.id == user_pool_id
            assert user_pool.password_policy is not None
            assert user_pool.deletion_protection is not None
            assert user_pool.advanced_security_mode is not None
            assert user_pool.tags is not None

    @mock_cognitoidp
    def test_get_user_pool_mfa_config(self):
        user_pool_name_1 = "user_pool_test_1"
        audit_info = self.set_mocked_audit_info()
        cognito_client_eu_west_1 = client("cognito-idp", region_name="eu-west-1")
        user_pool_id = cognito_client_eu_west_1.create_user_pool(
            PoolName=user_pool_name_1
        )["UserPool"]["Id"]
        cognito_client_eu_west_1.set_user_pool_mfa_config(
            UserPoolId=user_pool_id,
            SoftwareTokenMfaConfiguration={"Enabled": True},
            MfaConfiguration="ON",
        )
        cognito = Cognito(audit_info)
        assert len(cognito.user_pools) == 1
        for user_pool in cognito.user_pools:
            assert user_pool.name == user_pool_name_1
            assert user_pool.region == "eu-west-1"
            assert user_pool.id == user_pool_id
            assert user_pool.mfa_config is not None
            assert user_pool.mfa_config.sms_authentication == {}
            assert user_pool.mfa_config.software_token_mfa_authentication == {
                "Enabled": True
            }
            assert user_pool.mfa_config.status == "ON"
