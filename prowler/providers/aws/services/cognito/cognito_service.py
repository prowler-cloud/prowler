from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## CognitoIDP
class CognitoIDP(AWSService):
    def __init__(self, provider):
        super().__init__("cognito-idp", provider)

        self.user_pools = {}
        self.__threading_call__(self.__list_user_pools__)
        self.__describe_user_pools__()
        self.__get_user_pool_mfa_config__()
        self.__get_user_pool_risk_configuration__()

    def __list_user_pools__(self, regional_client):
        logger.info("Cognito - Listing User Pools...")
        try:
            user_pools_paginator = regional_client.get_paginator("list_user_pools")
            for page in user_pools_paginator.paginate(MaxResults=60):
                for user_pool in page["UserPools"]:
                    arn = f"arn:{self.audited_partition}:cognito-idp:{regional_client.region}:{self.audited_account}:userpool/{user_pool['Id']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        try:
                            self.user_pools[arn] = UserPool(
                                id=user_pool["Id"],
                                arn=arn,
                                name=user_pool["Name"],
                                region=regional_client.region,
                                last_modified=user_pool["LastModifiedDate"],
                                creation_date=user_pool["CreationDate"],
                                status=user_pool.get("Status", "Disabled"),
                            )
                        except Exception as error:
                            logger.error(
                                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_user_pools__(self):
        logger.info("Cognito - Describing User Pools...")
        try:
            for user_pool in self.user_pools.values():
                try:
                    user_pool_details = self.regional_clients[
                        user_pool.region
                    ].describe_user_pool(UserPoolId=user_pool.id)["UserPool"]
                    self.user_pools[user_pool.arn].password_policy = (
                        user_pool_details.get("Policies", {}).get("PasswordPolicy", {})
                    )
                    self.user_pools[user_pool.arn].deletion_protection = (
                        user_pool_details.get("DeletionProtection", "INACTIVE")
                    )
                    self.user_pools[user_pool.arn].advanced_security_mode = (
                        user_pool_details.get("UserPoolAddOns", {}).get(
                            "AdvancedSecurityMode", "OFF"
                        )
                    )
                    self.user_pools[user_pool.arn].tags = [
                        user_pool_details.get("UserPoolTags", "")
                    ]
                    self.user_pools[user_pool.arn].account_recovery_settings = (
                        user_pool_details.get("AccountRecoverySetting", {})
                    )
                    user_pool_client = self.regional_clients[
                        user_pool.region
                    ].describe_user_pool_client(
                        UserPoolId=user_pool.id,
                        ClientId=self.regional_clients[
                            user_pool.region
                        ].list_user_pool_clients(UserPoolId=user_pool.id)[
                            "UserPoolClients"
                        ][
                            0
                        ][
                            "ClientId"
                        ],
                    )[
                        "UserPoolClient"
                    ]
                    self.user_pools[user_pool.arn].user_pool_client = user_pool_client
                    self.user_pools[user_pool.arn].admin_create_user_config = (
                        user_pool_details.get("AdminCreateUserConfig", {})
                    )
                except Exception as error:
                    logger.error(
                        f"{user_pool.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{user_pool.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_user_pool_mfa_config__(self):
        logger.info("Cognito - Getting User Pool MFA Configuration...")
        try:
            for user_pool in self.user_pools.values():
                try:
                    mfa_config = self.regional_clients[
                        user_pool.region
                    ].get_user_pool_mfa_config(UserPoolId=user_pool.id)
                    if mfa_config["MfaConfiguration"] != "OFF":
                        self.user_pools[user_pool.arn].mfa_config = MFAConfig(
                            sms_authentication=mfa_config.get(
                                "SmsMfaConfiguration", {}
                            ),
                            software_token_mfa_authentication=mfa_config.get(
                                "SoftwareTokenMfaConfiguration", {}
                            ),
                            status=mfa_config["MfaConfiguration"],
                        )
                except Exception as error:
                    logger.error(
                        f"{user_pool.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{user_pool.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_user_pool_risk_configuration__(self):
        logger.info("Cognito - Getting User Pool Risk Configuration...")
        try:
            for user_pool in self.user_pools.values():
                try:
                    risk_configuration = self.regional_clients[
                        user_pool.region
                    ].describe_risk_configuration(UserPoolId=user_pool.id)
                    if risk_configuration.get("RiskConfiguration"):
                        self.user_pools[user_pool.arn].risk_configuration = (
                            RiskConfiguration(
                                compromised_credentials_risk_configuration=risk_configuration.get(
                                    "RiskConfiguration", {}
                                ).get(
                                    "CompromisedCredentialsRiskConfiguration", {}
                                ),
                                account_takeover_risk_configuration=risk_configuration.get(
                                    "RiskConfiguration", {}
                                ).get(
                                    "AccountTakeoverRiskConfiguration", {}
                                ),
                            )
                        )
                except Exception as error:
                    logger.error(
                        f"{user_pool.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{user_pool.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class CognitoIdentity(AWSService):
    def __init__(self, provider):
        super().__init__("cognito-identity", provider)
        self.identity_pools = {}
        self.__threading_call__(self.__list_identity_pools__)
        self.__describe_identity_pools__()

    def __list_identity_pools__(self, regional_client):
        logger.info("Cognito - Listing Identity Pools...")
        try:
            identity_pools_paginator = regional_client.get_paginator(
                "list_identity_pools"
            )
            for page in identity_pools_paginator.paginate(MaxResults=60):
                for identity_pool in page["IdentityPools"]:
                    arn = f"arn:{self.audited_partition}:cognito-identity:{regional_client.region}:{self.audited_account}:identitypool/{identity_pool['IdentityPoolId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        try:
                            self.identity_pools[arn] = IdentityPool(
                                id=identity_pool["IdentityPoolId"],
                                arn=arn,
                                name=identity_pool["IdentityPoolName"],
                                region=regional_client.region,
                            )
                        except Exception as error:
                            logger.error(
                                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_identity_pools__(self):
        logger.info("Cognito - Describing Identity Pools...")
        try:
            for identity_pool in self.identity_pools.values():
                try:
                    identity_pool_details = self.regional_clients[
                        identity_pool.region
                    ].describe_identity_pool(IdentityPoolId=identity_pool.id)
                    self.identity_pools[identity_pool.arn].associated_pools = (
                        identity_pool_details.get("CognitoIdentityProviders", {})
                    )
                except Exception as error:
                    logger.error(
                        f"{identity_pool.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{identity_pool.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class MFAConfig(BaseModel):
    sms_authentication: Optional[dict]
    software_token_mfa_authentication: Optional[dict]
    status: str


class RiskConfiguration(BaseModel):
    compromised_credentials_risk_configuration: Optional[dict]
    account_takeover_risk_configuration: Optional[dict]


class UserPool(BaseModel):
    id: str
    arn: str
    name: str
    region: str
    advanced_security_mode: str = "OFF"
    deletion_protection: str = "INACTIVE"
    last_modified: datetime
    creation_date: datetime
    status: str
    password_policy: Optional[dict]
    mfa_config: Optional[MFAConfig]
    tags: Optional[list] = []
    account_recovery_settings: Optional[dict]
    user_pool_client: Optional[dict] = {}
    risk_configuration: Optional[dict] = {}
    admin_create_user_config: Optional[dict] = {}


class IdentityPool(BaseModel):
    id: str
    arn: str
    name: str
    region: str
    associated_pools: dict = {}
