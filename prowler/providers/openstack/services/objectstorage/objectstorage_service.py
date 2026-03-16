from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from openstack import exceptions as openstack_exceptions

from prowler.lib.logger import logger
from prowler.providers.openstack.lib.service.service import OpenStackService


class ObjectStorage(OpenStackService):
    """Service wrapper using openstacksdk object-store APIs."""

    def __init__(self, provider) -> None:
        super().__init__(__class__.__name__, provider)
        self.containers: List[ObjectStorageContainer] = []
        self._list_containers()

    def _list_containers(self) -> None:
        """List all object storage containers across all audited regions."""
        logger.info("ObjectStorage - Listing containers...")
        for region, conn in self.regional_connections.items():
            try:
                for container in conn.object_store.containers():
                    # The list API only returns name/count/bytes; HEAD each
                    # container to retrieve ACLs, metadata, and versioning info.
                    try:
                        detail = conn.object_store.get_container_metadata(
                            getattr(container, "name", "")
                        )
                    except Exception as head_error:
                        logger.warning(
                            f"Could not HEAD container {getattr(container, 'name', '')}: {head_error}"
                        )
                        detail = container

                    metadata = getattr(detail, "metadata", None) or {}

                    # Extract versioning info (Swift supports two modes)
                    versions_location = getattr(detail, "versions_location", "") or ""
                    history_location = getattr(detail, "history_location", "") or ""
                    versioning_enabled = bool(versions_location or history_location)

                    self.containers.append(
                        ObjectStorageContainer(
                            id=getattr(container, "name", ""),
                            name=getattr(container, "name", ""),
                            region=region,
                            project_id=self.project_id,
                            object_count=getattr(detail, "count", 0),
                            bytes_used=getattr(detail, "bytes", 0),
                            read_ACL=getattr(detail, "read_ACL", "") or "",
                            write_ACL=getattr(detail, "write_ACL", "") or "",
                            versioning_enabled=versioning_enabled,
                            versions_location=versions_location,
                            history_location=history_location,
                            sync_to=getattr(detail, "sync_to", "") or "",
                            sync_key=getattr(detail, "sync_key", "") or "",
                            metadata=metadata if isinstance(metadata, dict) else {},
                        )
                    )
            except openstack_exceptions.SDKException as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                    f"Failed to list object storage containers in region {region}: {error}"
                )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                    f"Unexpected error listing object storage containers in region {region}: {error}"
                )


@dataclass
class ObjectStorageContainer:
    """Represents an OpenStack Swift container."""

    id: str
    name: str
    region: str
    project_id: str
    object_count: int
    bytes_used: int
    read_ACL: str
    write_ACL: str
    versioning_enabled: bool
    versions_location: str
    history_location: str
    sync_to: str
    sync_key: str
    metadata: Dict[str, str]
