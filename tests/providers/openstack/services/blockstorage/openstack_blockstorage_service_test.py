"""Tests for OpenStack BlockStorage service."""

from unittest.mock import MagicMock, patch

from openstack import exceptions as openstack_exceptions

from prowler.providers.openstack.services.blockstorage.blockstorage_service import (
    BackupResource,
    BlockStorage,
    SnapshotResource,
    VolumeResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class TestBlockStorageService:
    """Test suite for BlockStorage service."""

    def test_blockstorage_service_initialization(self):
        """Test BlockStorage service initializes correctly."""
        provider = set_mocked_openstack_provider()

        with (
            patch.object(BlockStorage, "_list_volumes", return_value=[]),
            patch.object(BlockStorage, "_list_snapshots", return_value=[]),
            patch.object(BlockStorage, "_list_backups", return_value=[]),
        ):
            block_storage = BlockStorage(provider)

            assert block_storage.service_name == "BlockStorage"
            assert block_storage.provider == provider
            assert block_storage.connection == provider.connection
            assert block_storage.region == OPENSTACK_REGION
            assert block_storage.project_id == OPENSTACK_PROJECT_ID
            assert block_storage.client == provider.connection.block_storage
            assert block_storage.volumes == []
            assert block_storage.snapshots == []
            assert block_storage.backups == []

    def test_blockstorage_list_volumes_success(self):
        """Test listing volumes successfully."""
        provider = set_mocked_openstack_provider()

        mock_volume = MagicMock()
        mock_volume.id = "vol-1"
        mock_volume.name = "Volume One"
        mock_volume.status = "in-use"
        mock_volume.size = 100
        mock_volume.volume_type = "encrypted"
        mock_volume.is_encrypted = True
        mock_volume.is_bootable = "true"
        mock_volume.is_multiattach = False
        mock_volume.attachments = [{"server_id": "server-1", "device": "/dev/vda"}]
        mock_volume.metadata = {"environment": "production"}
        mock_volume.availability_zone = "nova"
        mock_volume.snapshot_id = "snap-1"
        mock_volume.source_volume_id = None

        provider.connection.block_storage.volumes.return_value = [mock_volume]
        provider.connection.block_storage.snapshots.return_value = []
        provider.connection.block_storage.backups.return_value = []

        block_storage = BlockStorage(provider)

        assert len(block_storage.volumes) == 1
        assert isinstance(block_storage.volumes[0], VolumeResource)
        assert block_storage.volumes[0].id == "vol-1"
        assert block_storage.volumes[0].name == "Volume One"
        assert block_storage.volumes[0].status == "in-use"
        assert block_storage.volumes[0].size == 100
        assert block_storage.volumes[0].volume_type == "encrypted"
        assert block_storage.volumes[0].is_encrypted is True
        assert block_storage.volumes[0].is_bootable is True
        assert block_storage.volumes[0].is_multiattach is False
        assert len(block_storage.volumes[0].attachments) == 1
        assert block_storage.volumes[0].metadata == {"environment": "production"}
        assert block_storage.volumes[0].availability_zone == "nova"
        assert block_storage.volumes[0].snapshot_id == "snap-1"
        assert block_storage.volumes[0].source_volume_id == ""
        assert block_storage.volumes[0].project_id == OPENSTACK_PROJECT_ID
        assert block_storage.volumes[0].region == OPENSTACK_REGION

    def test_blockstorage_list_volumes_empty(self):
        """Test listing volumes when none exist."""
        provider = set_mocked_openstack_provider()
        provider.connection.block_storage.volumes.return_value = []
        provider.connection.block_storage.snapshots.return_value = []
        provider.connection.block_storage.backups.return_value = []

        block_storage = BlockStorage(provider)

        assert block_storage.volumes == []

    def test_blockstorage_list_volumes_sdk_exception(self):
        """Test handling SDKException when listing volumes."""
        provider = set_mocked_openstack_provider()
        provider.connection.block_storage.volumes.side_effect = (
            openstack_exceptions.SDKException("API error")
        )
        provider.connection.block_storage.snapshots.return_value = []
        provider.connection.block_storage.backups.return_value = []

        block_storage = BlockStorage(provider)

        assert block_storage.volumes == []

    def test_blockstorage_list_volumes_generic_exception(self):
        """Test handling generic exception when listing volumes."""
        provider = set_mocked_openstack_provider()
        provider.connection.block_storage.volumes.side_effect = Exception(
            "Unexpected error"
        )
        provider.connection.block_storage.snapshots.return_value = []
        provider.connection.block_storage.backups.return_value = []

        block_storage = BlockStorage(provider)

        assert block_storage.volumes == []

    def test_blockstorage_list_snapshots_success(self):
        """Test listing snapshots successfully."""
        provider = set_mocked_openstack_provider()

        mock_snapshot = MagicMock()
        mock_snapshot.id = "snap-1"
        mock_snapshot.name = "Snapshot One"
        mock_snapshot.status = "available"
        mock_snapshot.size = 50
        mock_snapshot.volume_id = "vol-1"
        mock_snapshot.metadata = {"backup": "daily"}

        provider.connection.block_storage.volumes.return_value = []
        provider.connection.block_storage.snapshots.return_value = [mock_snapshot]
        provider.connection.block_storage.backups.return_value = []

        block_storage = BlockStorage(provider)

        assert len(block_storage.snapshots) == 1
        assert isinstance(block_storage.snapshots[0], SnapshotResource)
        assert block_storage.snapshots[0].id == "snap-1"
        assert block_storage.snapshots[0].name == "Snapshot One"
        assert block_storage.snapshots[0].status == "available"
        assert block_storage.snapshots[0].size == 50
        assert block_storage.snapshots[0].volume_id == "vol-1"
        assert block_storage.snapshots[0].metadata == {"backup": "daily"}
        assert block_storage.snapshots[0].project_id == OPENSTACK_PROJECT_ID
        assert block_storage.snapshots[0].region == OPENSTACK_REGION

    def test_blockstorage_list_snapshots_sdk_exception(self):
        """Test handling SDKException when listing snapshots."""
        provider = set_mocked_openstack_provider()
        provider.connection.block_storage.volumes.return_value = []
        provider.connection.block_storage.snapshots.side_effect = (
            openstack_exceptions.SDKException("API error")
        )
        provider.connection.block_storage.backups.return_value = []

        block_storage = BlockStorage(provider)

        assert block_storage.snapshots == []

    def test_blockstorage_list_backups_success(self):
        """Test listing backups successfully."""
        provider = set_mocked_openstack_provider()

        mock_backup = MagicMock()
        mock_backup.id = "backup-1"
        mock_backup.name = "Backup One"
        mock_backup.status = "available"
        mock_backup.size = 100
        mock_backup.volume_id = "vol-1"
        mock_backup.is_incremental = True
        mock_backup.availability_zone = "nova"

        provider.connection.block_storage.volumes.return_value = []
        provider.connection.block_storage.snapshots.return_value = []
        provider.connection.block_storage.backups.return_value = [mock_backup]

        block_storage = BlockStorage(provider)

        assert len(block_storage.backups) == 1
        assert isinstance(block_storage.backups[0], BackupResource)
        assert block_storage.backups[0].id == "backup-1"
        assert block_storage.backups[0].name == "Backup One"
        assert block_storage.backups[0].status == "available"
        assert block_storage.backups[0].size == 100
        assert block_storage.backups[0].volume_id == "vol-1"
        assert block_storage.backups[0].is_incremental is True
        assert block_storage.backups[0].availability_zone == "nova"
        assert block_storage.backups[0].project_id == OPENSTACK_PROJECT_ID
        assert block_storage.backups[0].region == OPENSTACK_REGION

    def test_blockstorage_list_backups_sdk_exception(self):
        """Test handling SDKException when listing backups."""
        provider = set_mocked_openstack_provider()
        provider.connection.block_storage.volumes.return_value = []
        provider.connection.block_storage.snapshots.return_value = []
        provider.connection.block_storage.backups.side_effect = (
            openstack_exceptions.SDKException("API error")
        )

        block_storage = BlockStorage(provider)

        assert block_storage.backups == []

    def test_blockstorage_list_backups_generic_exception(self):
        """Test handling generic exception when listing backups."""
        provider = set_mocked_openstack_provider()
        provider.connection.block_storage.volumes.return_value = []
        provider.connection.block_storage.snapshots.return_value = []
        provider.connection.block_storage.backups.side_effect = Exception(
            "Unexpected error"
        )

        block_storage = BlockStorage(provider)

        assert block_storage.backups == []

    def test_blockstorage_service_inherits_from_base(self):
        """Test BlockStorage service inherits from OpenStackService."""
        provider = set_mocked_openstack_provider()

        with (
            patch.object(BlockStorage, "_list_volumes", return_value=[]),
            patch.object(BlockStorage, "_list_snapshots", return_value=[]),
            patch.object(BlockStorage, "_list_backups", return_value=[]),
        ):
            block_storage = BlockStorage(provider)

            assert hasattr(block_storage, "service_name")
            assert hasattr(block_storage, "provider")
            assert hasattr(block_storage, "connection")
            assert hasattr(block_storage, "session")
            assert hasattr(block_storage, "region")
            assert hasattr(block_storage, "project_id")
            assert hasattr(block_storage, "identity")
            assert hasattr(block_storage, "audit_config")
            assert hasattr(block_storage, "fixer_config")

    def test_volume_resource_dataclass(self):
        """Test VolumeResource dataclass has all required attributes."""
        volume = VolumeResource(
            id="vol-1",
            name="Test Volume",
            status="in-use",
            size=100,
            volume_type="encrypted",
            is_encrypted=True,
            is_bootable=True,
            is_multiattach=False,
            attachments=[{"server_id": "server-1"}],
            metadata={"env": "prod"},
            availability_zone="nova",
            snapshot_id="snap-1",
            source_volume_id="",
            project_id="project-1",
            region="RegionOne",
        )

        assert volume.id == "vol-1"
        assert volume.name == "Test Volume"
        assert volume.is_encrypted is True
        assert volume.is_bootable is True
        assert volume.is_multiattach is False

    def test_snapshot_resource_dataclass(self):
        """Test SnapshotResource dataclass has all required attributes."""
        snapshot = SnapshotResource(
            id="snap-1",
            name="Test Snapshot",
            status="available",
            size=50,
            volume_id="vol-1",
            metadata={},
            project_id="project-1",
            region="RegionOne",
        )

        assert snapshot.id == "snap-1"
        assert snapshot.volume_id == "vol-1"

    def test_backup_resource_dataclass(self):
        """Test BackupResource dataclass has all required attributes."""
        backup = BackupResource(
            id="backup-1",
            name="Test Backup",
            status="available",
            size=100,
            volume_id="vol-1",
            is_incremental=True,
            availability_zone="nova",
            project_id="project-1",
            region="RegionOne",
        )

        assert backup.id == "backup-1"
        assert backup.volume_id == "vol-1"
        assert backup.is_incremental is True
