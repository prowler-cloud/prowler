from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from openstack import exceptions as openstack_exceptions

from prowler.lib.logger import logger
from prowler.providers.openstack.lib.service.service import OpenStackService


class BlockStorage(OpenStackService):
    """Service wrapper using openstacksdk block storage (Cinder) APIs."""

    def __init__(self, provider) -> None:
        super().__init__(__class__.__name__, provider)
        self.volumes: List[VolumeResource] = []
        self.snapshots: List[SnapshotResource] = []
        self.backups: List[BackupResource] = []
        self._list_volumes()
        self._list_snapshots()
        self._list_backups()

    def _list_volumes(self) -> None:
        """List all block storage volumes across all audited regions."""
        logger.info("BlockStorage - Listing volumes...")
        for region, conn in self.regional_connections.items():
            try:
                for volume in conn.block_storage.volumes():
                    attachments = getattr(volume, "attachments", []) or []
                    self.volumes.append(
                        VolumeResource(
                            id=getattr(volume, "id", ""),
                            name=getattr(volume, "name", ""),
                            status=getattr(volume, "status", ""),
                            size=getattr(volume, "size", 0),
                            volume_type=getattr(volume, "volume_type", ""),
                            is_encrypted=getattr(volume, "is_encrypted", False),
                            is_bootable=str(
                                getattr(volume, "is_bootable", "false")
                            ).lower()
                            == "true",
                            is_multiattach=getattr(volume, "is_multiattach", False),
                            attachments=attachments,
                            metadata=getattr(volume, "metadata", {}),
                            availability_zone=getattr(volume, "availability_zone", ""),
                            snapshot_id=getattr(volume, "snapshot_id", "") or "",
                            source_volume_id=getattr(volume, "source_volume_id", "")
                            or "",
                            project_id=self.project_id,
                            region=region,
                        )
                    )
            except openstack_exceptions.SDKException as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                    f"Failed to list block storage volumes in region {region}: {error}"
                )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                    f"Unexpected error listing block storage volumes in region {region}: {error}"
                )

    def _list_snapshots(self) -> None:
        """List all block storage snapshots across all audited regions."""
        logger.info("BlockStorage - Listing snapshots...")
        for region, conn in self.regional_connections.items():
            try:
                for snapshot in conn.block_storage.snapshots():
                    self.snapshots.append(
                        SnapshotResource(
                            id=getattr(snapshot, "id", ""),
                            name=getattr(snapshot, "name", ""),
                            status=getattr(snapshot, "status", ""),
                            size=getattr(snapshot, "size", 0),
                            volume_id=getattr(snapshot, "volume_id", ""),
                            metadata=getattr(snapshot, "metadata", {}),
                            project_id=self.project_id,
                            region=region,
                        )
                    )
            except openstack_exceptions.SDKException as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                    f"Failed to list block storage snapshots in region {region}: {error}"
                )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                    f"Unexpected error listing block storage snapshots in region {region}: {error}"
                )

    def _list_backups(self) -> None:
        """List all block storage backups across all audited regions."""
        logger.info("BlockStorage - Listing backups...")
        for region, conn in self.regional_connections.items():
            try:
                for backup in conn.block_storage.backups():
                    self.backups.append(
                        BackupResource(
                            id=getattr(backup, "id", ""),
                            name=getattr(backup, "name", ""),
                            status=getattr(backup, "status", ""),
                            size=getattr(backup, "size", 0),
                            volume_id=getattr(backup, "volume_id", ""),
                            is_incremental=getattr(backup, "is_incremental", False),
                            availability_zone=getattr(backup, "availability_zone", ""),
                            project_id=self.project_id,
                            region=region,
                        )
                    )
            except openstack_exceptions.SDKException as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                    f"Failed to list block storage backups in region {region}: {error}"
                )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                    f"Unexpected error listing block storage backups in region {region}: {error}"
                )


@dataclass
class VolumeResource:
    """Represents an OpenStack block storage volume."""

    id: str
    name: str
    status: str
    size: int
    volume_type: str
    is_encrypted: bool
    is_bootable: bool
    is_multiattach: bool
    attachments: List[Dict]
    metadata: Dict[str, str]
    availability_zone: str
    snapshot_id: str
    source_volume_id: str
    project_id: str
    region: str


@dataclass
class SnapshotResource:
    """Represents an OpenStack block storage snapshot."""

    id: str
    name: str
    status: str
    size: int
    volume_id: str
    metadata: Dict[str, str]
    project_id: str
    region: str


@dataclass
class BackupResource:
    """Represents an OpenStack block storage backup."""

    id: str
    name: str
    status: str
    size: int
    volume_id: str
    is_incremental: bool
    availability_zone: str
    project_id: str
    region: str
