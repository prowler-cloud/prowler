from typing import Dict, List

from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class ACMPCA(AWSService):
    def __init__(self, provider):
        # The boto3 client identifier for AWS Private CA is "acm-pca"
        super().__init__("acm-pca", provider)
        self.certificate_authorities = {}
        self.__threading_call__(self._list_certificate_authorities)

    def _list_certificate_authorities(self, regional_client):
        logger.info("ACM PCA - Listing Certificate Authorities...")
        try:
            paginator = regional_client.get_paginator("list_certificate_authorities")
            for page in paginator.paginate():
                for ca in page.get("CertificateAuthorities", []):
                    arn = ca.get("Arn", "")
                    if not arn:
                        continue
                    if self.audit_resources and not is_resource_filtered(
                        arn, self.audit_resources
                    ):
                        continue
                    config = ca.get("CertificateAuthorityConfiguration", {})
                    self.certificate_authorities[arn] = CertificateAuthority(
                        arn=arn,
                        id=arn.split("/")[-1],
                        region=regional_client.region,
                        status=ca.get("Status", ""),
                        type=ca.get("Type", ""),
                        usage_mode=ca.get("UsageMode", ""),
                        key_algorithm=config.get("KeyAlgorithm", ""),
                        signing_algorithm=config.get("SigningAlgorithm", ""),
                        tags=[],
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class CertificateAuthority(BaseModel):
    arn: str
    id: str
    region: str
    status: str = ""
    type: str = ""
    usage_mode: str = ""
    key_algorithm: str = ""
    signing_algorithm: str = ""
    tags: List[Dict[str, str]] = Field(default_factory=list)
