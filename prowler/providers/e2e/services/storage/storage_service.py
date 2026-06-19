from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.e2e.lib.service.service import E2eService


class Storage(E2eService):
    """Service class for E2E Cloud storage resources."""

    def __init__(self, provider):
        super().__init__("storage", provider)
        self.block_volumes: list[BlockVolume] = []
        self.buckets: list[StorageBucket] = []
        self._fetch_block_volumes()
        self._fetch_buckets()

    def _fetch_block_volumes(self):
        for location in self.provider.session.locations:
            try:
                volumes = self.client.paginate(
                    "/block_storage/",
                    location=location,
                )
                for item in volumes:
                    vm_detail = item.get("vm_detail", {}) or {}
                    self.block_volumes.append(
                        BlockVolume(
                            id=str(item.get("block_id", "")),
                            name=item.get("name", ""),
                            location=location,
                            status=item.get("status", ""),
                            size_string=item.get("size_string", ""),
                            is_attached=bool(vm_detail),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"storage - Error fetching block volumes in {location}: {error}"
                )

    def _fetch_buckets(self):
        for location in self.provider.session.locations:
            try:
                buckets = self.client.paginate(
                    "/storage/buckets/",
                    location=location,
                )
                for item in buckets:
                    self.buckets.append(
                        StorageBucket(
                            id=str(item.get("id", "")),
                            name=item.get("name", ""),
                            location=location,
                            status=item.get("status", ""),
                            versioning_status=item.get("versioning_status", "Off"),
                            is_public_access_enabled=bool(
                                item.get("is_public_access_enabled", False)
                            ),
                            is_encryption_enabled=bool(
                                item.get("is_encryption_enabled", False)
                            ),
                            is_lock_enabled=bool(item.get("is_lock_enabled", False)),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"storage - Error fetching buckets in {location}: {error}"
                )


class BlockVolume(BaseModel):
    id: str
    name: str
    location: str
    status: str = ""
    size_string: str = ""
    is_attached: bool = False

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name


class StorageBucket(BaseModel):
    id: str
    name: str
    location: str
    status: str = ""
    versioning_status: str = "Off"
    is_public_access_enabled: bool = False
    is_encryption_enabled: bool = False
    is_lock_enabled: bool = False

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name
