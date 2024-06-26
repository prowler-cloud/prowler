import mock
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cognito.cognito_service import (
    AccountTakeoverRiskConfiguration,
    CognitoIdentity,
    CognitoIDP,
    CompromisedCredentialsRiskConfiguration,
    IdentityPoolRoles,
    RiskConfiguration,
    UserPoolClient,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_Cognito_Service:
    # Test Cognito Service
    @mock_aws
    def test_service_idp(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIDP(aws_provider)
        assert cognito.service == "cognito-idp"

    # Test Cognito client
    @mock_aws
    def test_client_idp(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIDP(aws_provider)
        for regional_client in cognito.regional_clients.values():
            assert regional_client.__class__.__name__ == "CognitoIdentityProvider"

    # Test Cognito session
    @mock_aws
    def test__get_session_idp__(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIDP(aws_provider)
        assert cognito.session.__class__.__name__ == "Session"

    # Test Cognito Session
    @mock_aws
    def test_audited_account_idp(self):
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
            assert user_pool.account_recovery_settings is not None
            assert user_pool.tags is not None

    @mock_aws
    def test_list_user_pool_clients(self):
        cognito_client = mock.MagicMock()
        user_pool_arn = "user_pool_test_1"
        cognito_client[user_pool_arn].id = "user_pool_id"
        cognito_client[user_pool_arn].arn = user_pool_arn
        cognito_client[user_pool_arn].name = "user_pool_name"
        cognito_client[user_pool_arn].region = "eu-west-1"
        cognito_client[user_pool_arn].user_pool_clients["user_pool_client_id"] = (
            UserPoolClient(
                id="user_pool_client_id",
                name="user_pool_client_name",
                arn=f"{user_pool_arn}/client/user_pool_client_id",
                region="eu-west-1",
            )
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ):
            for user_pool in cognito_client.user_pools.values():
                assert user_pool.region == "eu-west-1"
                assert user_pool.name == "user_pool_name"
                assert user_pool.id == "user_pool_id"
                assert (
                    user_pool.user_pool_clients["user_pool_client_id"].id
                    == "user_pool_client_id"
                )
                assert (
                    user_pool.user_pool_clients["user_pool_client_id"].name
                    == "user_pool_client_name"
                )
                assert (
                    user_pool.user_pool_clients["user_pool_client_id"].region
                    == "eu-west-1"
                )
                assert (
                    user_pool.user_pool_clients["user_pool_client_id"].arn
                    == f"{user_pool_arn}/client/user_pool_client_id"
                )

    @mock_aws
    def test_describe_user_pool_clients(self):
        cognito_client = mock.MagicMock()
        user_pool_arn = "user_pool_test_1"
        cognito_client[user_pool_arn].id = "user_pool_id"
        cognito_client[user_pool_arn].arn = user_pool_arn
        cognito_client[user_pool_arn].name = "user_pool_name"
        cognito_client[user_pool_arn].region = "eu-west-1"
        cognito_client[user_pool_arn].user_pool_clients["user_pool_client_id"] = (
            UserPoolClient(
                id="user_pool_client_id",
                name="user_pool_client_name",
                region="eu-west-1",
                arn=f"{user_pool_arn}/client/user_pool_client_id",
                prevent_user_existence_errors="ENABLED",
                enable_token_revocation=True,
            )
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ):
            for user_pool in cognito_client.user_pools.values():
                assert user_pool.region == "eu-west-1"
                assert user_pool.name == "user_pool_name"
                assert user_pool.id == "user_pool_id"
                assert (
                    user_pool.user_pool_clients["user_pool_client_id"].id
                    == "user_pool_client_id"
                )
                assert (
                    user_pool.user_pool_clients["user_pool_client_id"].name
                    == "user_pool_client_name"
                )
                assert (
                    user_pool.user_pool_clients["user_pool_client_id"].region
                    == "eu-west-1"
                )
                assert (
                    user_pool.user_pool_clients["user_pool_client_id"].arn
                    == f"{user_pool_arn}/client/user_pool_client_id"
                )
                assert (
                    user_pool.user_pool_clients[
                        "user_pool_client_id"
                    ].prevent_user_existence_errors
                    == "ENABLED"
                )
                assert (
                    user_pool.user_pool_clients[
                        "user_pool_client_id"
                    ].enable_token_revocation
                    is True
                )

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

    def test_get_user_pool_risk_configuration(self):
        cognito_client = mock.MagicMock()
        user_pool_arn = "user_pool_test_1"
        cognito_client.user_pools[user_pool_arn].id = "user_pool_id"
        cognito_client.user_pools[user_pool_arn].arn = user_pool_arn
        cognito_client.user_pools[user_pool_arn].name = "user_pool_name"
        cognito_client.user_pools[user_pool_arn].region = "eu-west-1"
        cognito_client.user_pools[user_pool_arn].risk_configuration = RiskConfiguration(
            compromised_credentials_risk_configuration=CompromisedCredentialsRiskConfiguration(
                event_filter=["PASSWORD_CHANGE", "SIGN_UP", "SIGN_IN"],
                actions="BLOCK",
            ),
            account_takeover_risk_configuration=AccountTakeoverRiskConfiguration(
                low_action="BLOCK",
                medium_action="BLOCK",
                high_action="BLOCK",
            ),
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_idp_client.cognito_idp_client",
            new=cognito_client,
        ):
            for user_pool in cognito_client.user_pools.values():
                assert user_pool.region == "eu-west-1"
                assert user_pool.name == "user_pool_name"
                assert user_pool.id == "user_pool_id"
                assert (
                    user_pool.risk_configuration.compromised_credentials_risk_configuration
                    == CompromisedCredentialsRiskConfiguration(
                        event_filter=["PASSWORD_CHANGE", "SIGN_UP", "SIGN_IN"],
                        actions="BLOCK",
                    )
                )
                assert (
                    user_pool.risk_configuration.account_takeover_risk_configuration.low_action
                    == "BLOCK"
                )
                assert (
                    user_pool.risk_configuration.account_takeover_risk_configuration.medium_action
                    == "BLOCK"
                )
                assert (
                    user_pool.risk_configuration.account_takeover_risk_configuration.high_action
                    == "BLOCK"
                )

    @mock_aws
    def test_service_identity(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIdentity(aws_provider)
        assert cognito.service == "cognito-identity"

    # Test Cognito client
    @mock_aws
    def test_client_identity(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIdentity(aws_provider)
        for regional_client in cognito.regional_clients.values():
            assert regional_client.__class__.__name__ == "CognitoIdentity"

    # Test Cognito session
    @mock_aws
    def test__get_session_identity__(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIdentity(aws_provider)
        assert cognito.session.__class__.__name__ == "Session"

    # Test Cognito Session
    @mock_aws
    def test_audited_account_identity(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito = CognitoIdentity(aws_provider)
        assert cognito.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_list_identity_pools(self):
        identity_pool_name_1 = "identity_pool_test_1"
        identity_pool_name_2 = "identity_pool_test_2"
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito_client_eu_west_1 = client("cognito-identity", region_name="eu-west-1")
        cognito_client_us_east_1 = client("cognito-identity", region_name="us-east-1")
        cognito_client_eu_west_1.create_identity_pool(
            IdentityPoolName=identity_pool_name_1, AllowUnauthenticatedIdentities=True
        )
        cognito_client_us_east_1.create_identity_pool(
            IdentityPoolName=identity_pool_name_2, AllowUnauthenticatedIdentities=True
        )
        cognito = CognitoIdentity(aws_provider)
        assert len(cognito.identity_pools) == 2
        for identity_pool in cognito.identity_pools.values():
            assert (
                identity_pool.name == identity_pool_name_1
                or identity_pool.name == identity_pool_name_2
            )
            assert (
                identity_pool.region == "eu-west-1"
                or identity_pool.region == "us-east-1"
            )

    @mock_aws
    def test_describe_identity_pools(self):
        identity_pool_name_1 = "identity_pool_test_1"
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        cognito_client_eu_west_1 = client("cognito-identity", region_name="eu-west-1")
        identity_pool_id = cognito_client_eu_west_1.create_identity_pool(
            IdentityPoolName=identity_pool_name_1, AllowUnauthenticatedIdentities=True
        )["IdentityPoolId"]
        cognito = CognitoIdentity(aws_provider)
        assert len(cognito.identity_pools) == 1
        for identity_pool in cognito.identity_pools.values():
            assert identity_pool.name == identity_pool_name_1
            assert identity_pool.region == "eu-west-1"
            assert identity_pool.id == identity_pool_id
            assert identity_pool.associated_pools is not None
            assert identity_pool.tags is not None
            assert identity_pool.allow_unauthenticated_identities is not None

    @mock_aws
    def test_get_identity_pool_tags(self):
        cognito_identity_client = mock.MagicMock()
        identity_pool_arn = "identity_pool_test_1"
        cognito_identity_client[identity_pool_arn].id = "identity_pool_id"
        cognito_identity_client[identity_pool_arn].arn = identity_pool_arn
        cognito_identity_client[identity_pool_arn].name = "identity_pool_name"
        cognito_identity_client[identity_pool_arn].region = "eu-west-1"
        cognito_identity_client[identity_pool_arn].tags = {"tag_key": "tag_value"}
        cognito_identity_client[identity_pool_arn].allow_unauthenticated_identities = (
            True
        )
        cognito_identity_client[identity_pool_arn].roles = IdentityPoolRoles(
            authenticated="authenticated_role",
            unauthenticated="unauthenticated_role",
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.cognito.cognito_identity_client.cognito_identity_client",
            new=cognito_identity_client,
        ):
            for identity_pool in cognito_identity_client.identity_pools.values():
                assert identity_pool.region == "eu-west-1"
                assert identity_pool.name == "identity_pool_name"
                assert identity_pool.id == "identity_pool_id"
                assert identity_pool.tags == {"tag_key": "tag_value"}
                assert identity_pool.allow_unauthenticated_identities is True
                assert identity_pool.roles.authenticated == "authenticated_role"
                assert identity_pool.roles.unauthenticated == "unauthenticated_role"
