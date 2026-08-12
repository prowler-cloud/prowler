from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class TMS(HuaweiCloudService):
    """
    TMS (Tag Management Service) class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud TMS service
    to retrieve predefined tags.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.predefined_tags: List[PredefinedTag] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_predefined_tags()

    def _load_mock_data(self):
        """Load mock data for testing."""
        self.predefined_tags = [
            PredefinedTag(key="environment", value="production"),
            PredefinedTag(key="owner", value="platform-team"),
            PredefinedTag(key="project", value="huaweicloud-audit"),
        ]

    def _list_predefined_tags(self):
        """List all predefined tags."""
        if not self.client:
            return

        region = self.region
        client = self.client
        logger.info(f"TMS - Listing Predefined Tags from {region}...")

        try:
            from huaweicloudsdktms.v1 import ListPredefineTagsRequest

            request = ListPredefineTagsRequest()
            response = self._call_with_retries(client.list_predefine_tags, request)

            if response and response.tags:
                for tag_data in response.tags:
                    self.predefined_tags.append(
                        PredefinedTag(
                            key=getattr(tag_data, "key", ""),
                            value=getattr(tag_data, "value", ""),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class PredefinedTag(BaseModel):
    """TMS Predefined Tag model."""

    key: str = ""
    value: str = ""
