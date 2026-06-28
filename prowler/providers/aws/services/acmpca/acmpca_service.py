from __future__ import annotations

from typing import Any, Dict, List

from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.service.service import AWSService


class ACMPCA(AWSService):
    """AWS Private CA service class to list certificate authorities."""

    def __init__(self, provider: AwsProvider) -> None:
        """Initialize the AWS Private CA service.

        Args:
            provider: AWS provider instance with session and audit context.
        """

        # The boto3 client identifier for AWS Private CA is "acm-pca"
        super().__init__("acm-pca", provider)
        self.certificate_authorities: dict[str, CertificateAuthority] = {}
        self.__threading_call__(self._list_certificate_authorities)

    def _list_certificate_authorities(self, regional_client: Any) -> None:
        """List AWS Private CAs and their tags in a region.

        Args:
            regional_client: Regional AWS Private CA client.
        """

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
                    tags = []
                    try:
                        tags = regional_client.list_tags(
                            CertificateAuthorityArn=arn
                        ).get("Tags", [])
                    except Exception as error:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    self.certificate_authorities[arn] = CertificateAuthority(
                        arn=arn,
                        id=arn.split("/")[-1],
                        region=regional_client.region,
                        status=ca.get("Status", ""),
                        type=ca.get("Type", ""),
                        usage_mode=ca.get("UsageMode", ""),
                        key_algorithm=config.get("KeyAlgorithm", ""),
                        signing_algorithm=config.get("SigningAlgorithm", ""),
                        tags=tags,
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class CertificateAuthority(BaseModel):
    """AWS Private Certificate Authority metadata.

    Attributes:
        arn: Certificate authority ARN.
        id: Certificate authority identifier.
        region: AWS region where the certificate authority exists.
        status: Certificate authority lifecycle status.
        type: Certificate authority type.
        usage_mode: Certificate authority usage mode.
        key_algorithm: Key algorithm configured for the certificate authority.
        signing_algorithm: Signing algorithm configured for the certificate authority.
        tags: Tags attached to the certificate authority.
    """

    arn: str
    id: str
    region: str
    status: str = ""
    type: str = ""
    usage_mode: str = ""
    key_algorithm: str = ""
    signing_algorithm: str = ""
    tags: List[Dict[str, str]] = Field(default_factory=list)
