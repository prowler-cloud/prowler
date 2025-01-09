from json import loads
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class SES(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("sesv2", provider)
        self.email_identities = {}
        self.__threading_call__(self._list_email_identities)
        self.__threading_call__(
            self._get_email_identities, self.email_identities.values()
        )

    def _list_email_identities(self, regional_client):
        logger.info("SES - describing identities...")
        try:
            response = regional_client.list_email_identities()
            for email_identity in response["EmailIdentities"]:
                identity_arn = f"arn:{self.audited_partition}:ses:{regional_client.region}:{self.audited_account}:identity/{email_identity['IdentityName']}"
                if not self.audit_resources or (
                    is_resource_filtered(identity_arn, self.audit_resources)
                ):
                    self.email_identities[identity_arn] = Identity(
                        arn=identity_arn,
                        type=email_identity["IdentityType"],
                        name=email_identity["IdentityName"],
                        region=regional_client.region,
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_email_identities(self, identity):
        try:
            logger.info("SES - describing email identities ...")
            try:
                regional_client = self.regional_clients[identity.region]
                identity_attributes = regional_client.get_email_identity(
                    EmailIdentity=identity.name
                )
                for _, content in identity_attributes["Policies"].items():
                    identity.policy = loads(content)
                identity.tags = identity_attributes["Tags"]

            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Identity(BaseModel):
    name: str
    arn: str
    region: str
    type: Optional[str]
    policy: Optional[dict] = None
    tags: Optional[list] = []
