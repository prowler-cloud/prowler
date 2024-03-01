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
                    user_pool.password_policy = user_pool_details.get(
                        "Policies", {}
                    ).get("PasswordPolicy", {})
                    user_pool.deletion_protection = user_pool_details.get(
                        "DeletionProtection", "INACTIVE"
                    )
                    user_pool.advanced_security_mode = user_pool_details.get(
                        "UserPoolAddOns", {}
                    ).get("AdvancedSecurityMode", "OFF")
                    user_pool.tags = [user_pool_details.get("UserPoolTags", "")]
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
                        user_pool.mfa_config = MFAConfig(
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


class MFAConfig(BaseModel):
    sms_authentication: Optional[dict]
    software_token_mfa_authentication: Optional[dict]
    status: str


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
