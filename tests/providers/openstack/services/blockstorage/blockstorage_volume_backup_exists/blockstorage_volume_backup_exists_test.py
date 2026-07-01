"""Tests for blockstorage_volume_backup_exists check."""

from unittest import mock

from prowler.providers.openstack.services.blockstorage.blockstorage_service import (
    BackupResource,
    VolumeResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_blockstorage_volume_backup_exists:
    """Test suite for blockstorage_volume_backup_exists check."""

    def test_no_volumes(self):
        """Test when no volumes exist."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = []
        blockstorage_client.backups = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_backup_exists.blockstorage_volume_backup_exists.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_backup_exists.blockstorage_volume_backup_exists import (
                blockstorage_volume_backup_exists,
            )

            check = blockstorage_volume_backup_exists()
            result = check.execute()

            assert len(result) == 0

    def test_volume_with_backup(self):
        """Test volume with backups (PASS)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-1",
                name="Backed Up Volume",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={},
                availability_zone="nova",
                snapshot_id="",
                source_volume_id="",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]
        blockstorage_client.backups = [
            BackupResource(
                id="backup-1",
                name="Backup 1",
                status="available",
                size=100,
                volume_id="vol-1",
                is_incremental=False,
                availability_zone="nova",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
            BackupResource(
                id="backup-2",
                name="Backup 2",
                status="available",
                size=100,
                volume_id="vol-1",
                is_incremental=True,
                availability_zone="nova",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_backup_exists.blockstorage_volume_backup_exists.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_backup_exists.blockstorage_volume_backup_exists import (
                blockstorage_volume_backup_exists,
            )

            check = blockstorage_volume_backup_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Volume Backed Up Volume (vol-1) has 2 backup(s)."
            )
            assert result[0].resource_id == "vol-1"
            assert result[0].resource_name == "Backed Up Volume"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_volume_without_backup(self):
        """Test volume without any backups (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-2",
                name="No Backup Volume",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={},
                availability_zone="nova",
                snapshot_id="",
                source_volume_id="",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]
        blockstorage_client.backups = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_backup_exists.blockstorage_volume_backup_exists.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_backup_exists.blockstorage_volume_backup_exists import (
                blockstorage_volume_backup_exists,
            )

            check = blockstorage_volume_backup_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Volume No Backup Volume (vol-2) does not have any backups."
            )
            assert result[0].resource_id == "vol-2"
            assert result[0].resource_name == "No Backup Volume"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_volumes_mixed(self):
        """Test multiple volumes with mixed backup status."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-pass",
                name="Pass",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={},
                availability_zone="nova",
                snapshot_id="",
                source_volume_id="",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
            VolumeResource(
                id="vol-fail",
                name="Fail",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={},
                availability_zone="nova",
                snapshot_id="",
                source_volume_id="",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
        ]
        blockstorage_client.backups = [
            BackupResource(
                id="backup-1",
                name="Backup 1",
                status="available",
                size=100,
                volume_id="vol-pass",
                is_incremental=False,
                availability_zone="nova",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_backup_exists.blockstorage_volume_backup_exists.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_backup_exists.blockstorage_volume_backup_exists import (
                blockstorage_volume_backup_exists,
            )

            check = blockstorage_volume_backup_exists()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
