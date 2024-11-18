import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class SecretsManager(AWSService):
    """AWS Secrets Manager service class to list secrets."""

    def __init__(self, provider):
        """Initialize SecretsManager service.

        Args:
            provider: The AWS provider instance.
        """
        super().__init__(__class__.__name__, provider)
        self.secrets = {}
        self.__threading_call__(self._list_secrets)
        self.__threading_call__(self._get_resource_policy, self.secrets.values())

    def _list_secrets(self, regional_client):
        """List all secrets in the region.

        Args:
            regional_client: The regional AWS client to list secrets.
        """
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
                            rotation_enabled=secret.get("RotationEnabled", False),
                            last_rotated_date=secret.get(
                                "LastRotatedDate", datetime.min
                            ).replace(tzinfo=timezone.utc),
                            last_accessed_date=secret.get(
                                "LastAccessedDate", datetime.min
                            ).replace(tzinfo=timezone.utc),
                            tags=secret.get("Tags"),
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _get_resource_policy(self, secret):
        logger.info("SecretsManager - Getting Resource Policy...")
        try:
            secret_policy = self.regional_clients[secret.region].get_resource_policy(
                SecretId=secret.arn
            )
            if secret_policy.get("ResourcePolicy"):
                secret.policy = json.loads(secret_policy["ResourcePolicy"])
        except Exception as error:
            logger.error(
                f"{self.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )


class Secret(BaseModel):
    arn: str
    name: str
    region: str
    policy: Optional[dict] = None
    rotation_enabled: bool = False
    last_rotated_date: datetime
    last_accessed_date: datetime
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)
