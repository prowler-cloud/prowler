from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class PredefinedTag(BaseModel):
    """TMS predefined tag."""

    key: str = ""
    value: str = ""


class PredefinedTagsConfiguration(BaseModel):
    """Account-level TMS predefined tags configuration."""

    id: str
    name: str
    region: str
    arn: str
    predefined_tags: list[PredefinedTag]


class TMS(HuaweiCloudService):
    """
    TMS (Tag Management Service) class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud TMS service
    to retrieve predefined tags.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.predefined_tags: list[PredefinedTag] | None = []

        if getattr(self.session, "is_mock", False):
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
            self.predefined_tags = None
            return

        region = self.region
        client = self.client
        logger.info(f"TMS - Listing Predefined Tags from {region}...")

        try:
            from huaweicloudsdktms.v1 import ListPredefineTagsRequest

            marker = None
            while True:
                request = ListPredefineTagsRequest(limit=1000, marker=marker)
                response = self._call_with_retries(client.list_predefine_tags, request)
                tags = getattr(response, "tags", None) or []
                for tag_data in tags:
                    self.predefined_tags.append(
                        PredefinedTag(key=tag_data.key, value=tag_data.value)
                    )

                total_count = getattr(response, "total_count", None)
                next_marker = getattr(response, "marker", None)
                if (
                    not tags
                    or total_count is not None
                    and len(self.predefined_tags) >= total_count
                    or not next_marker
                    or next_marker == marker
                ):
                    break
                marker = next_marker

        except Exception as error:
            self.predefined_tags = None
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
