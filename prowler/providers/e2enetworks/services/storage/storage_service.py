from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.e2enetworks.lib.service.service import E2eNetworksService


class Storage(E2eNetworksService):
    """Service class for E2E Networks storage resources."""

    def __init__(self, provider):
        super().__init__("storage", provider)
        self.block_volumes: list[BlockVolume] = []
        self.efs_volumes: list[EfsVolume] = []
        self.epfs_volumes: list[EpfsVolume] = []
        self._fetch_block_volumes()
        self._fetch_efs_volumes()
        self._fetch_epfs_volumes()

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
                    f"storage - Error fetching block volumes in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _fetch_efs_volumes(self):
        for location in self.provider.session.locations:
            try:
                volumes = self.client.paginate("/efs/", location=location)
                for item in volumes:
                    self.efs_volumes.append(
                        EfsVolume(
                            id=str(item.get("id", "")),
                            name=item.get("name", ""),
                            location=location,
                            status=item.get("status", ""),
                            vpc_id=str(item.get("vpc_id", "")),
                            is_backup_enabled=bool(
                                item.get("is_backup_enabled", False)
                            ),
                            is_all_vpc_resources_allowed=bool(
                                item.get("is_all_vpc_resources_allowed", False)
                            ),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"storage - Error fetching EFS volumes in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _fetch_epfs_volumes(self):
        for location in self.provider.session.locations:
            try:
                all_items: list = []
                page = 1
                total_pages = 1
                while page <= total_pages:
                    payload = self.client.get(
                        "/epfs/",
                        location=location,
                        params={"page": page, "page_size": 100},
                    )
                    data = payload.get("data", [])
                    if isinstance(data, list):
                        all_items.extend(data)
                    total_pages = int(payload.get("total_page_number", page))
                    if not data:
                        break
                    page += 1

                for item in all_items:
                    vpc = item.get("vpc", {}) or {}
                    self.epfs_volumes.append(
                        EpfsVolume(
                            id=str(item.get("id", "")),
                            name=item.get("name", ""),
                            location=location,
                            vpc_network_id=str(vpc.get("network_id", "")),
                            vpc_name=vpc.get("name", ""),
                            deleted=bool(item.get("deleted", False)),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"storage - Error fetching EPFS volumes in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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


class EfsVolume(BaseModel):
    id: str
    name: str
    location: str
    status: str = ""
    vpc_id: str = ""
    is_backup_enabled: bool = False
    is_all_vpc_resources_allowed: bool = False

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name


class EpfsVolume(BaseModel):
    id: str
    name: str
    location: str
    vpc_network_id: str = ""
    vpc_name: str = ""
    deleted: bool = False

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name
