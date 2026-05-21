from typing import Dict, List

from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class RolesAnywhere(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.trust_anchors = {}
        self.__threading_call__(self._list_trust_anchors)

    def _list_trust_anchors(self, regional_client):
        logger.info("RolesAnywhere - Listing Trust Anchors...")
        try:
            paginator = regional_client.get_paginator("list_trust_anchors")
            for page in paginator.paginate():
                for ta in page.get("trustAnchors", []):
                    arn = ta.get("trustAnchorArn", "")
                    if not arn:
                        continue
                    if self.audit_resources and not is_resource_filtered(
                        arn, self.audit_resources
                    ):
                        continue
                    source = ta.get("source", {}) or {}
                    source_data = source.get("sourceData", {}) or {}
                    self.trust_anchors[arn] = TrustAnchor(
                        arn=arn,
                        id=ta.get("trustAnchorId", ""),
                        name=ta.get("name", ""),
                        region=regional_client.region,
                        enabled=ta.get("enabled", False),
                        source_type=source.get("sourceType", ""),
                        acm_pca_arn=source_data.get("acmPcaArn", ""),
                        tags=[],
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class TrustAnchor(BaseModel):
    arn: str
    id: str
    name: str
    region: str
    enabled: bool = False
    source_type: str = ""
    acm_pca_arn: str = ""
    tags: List[Dict[str, str]] = Field(default_factory=list)
