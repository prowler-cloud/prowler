from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## SecretsManager
class SecretsManager(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.secrets = {}
        self.__threading_call__(self.__list_secrets__)

    def __list_secrets__(self, regional_client):
        logger.info("SecretsManager - Listing Secrets...")
        try:
            list_secrets_paginator = regional_client.get_paginator("list_secrets")
            for page in list_secrets_paginator.paginate():
                for secret in page["SecretList"]:
                    if not self.audit_resources or (
                        is_resource_filtered(secret["ARN"], self.audit_resources)
                    ):
                        # We must use the Secret ARN as the dict key to have unique keys
                        self.secrets[secret["ARN"]] = Secret(
                            arn=secret["ARN"],
                            name=secret["Name"],
                            region=regional_client.region,
                            tags=secret.get("Tags"),
                        )
                        if "RotationEnabled" in secret:
                            self.secrets[secret["ARN"]].rotation_enabled = secret[
                                "RotationEnabled"
                            ]

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )


class Secret(BaseModel):
    arn: str
    name: str
    region: str
    rotation_enabled: bool = False
    tags: Optional[list] = []
