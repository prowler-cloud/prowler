"""Tests for blockstorage_snapshot_not_orphaned check."""

from unittest import mock

from prowler.providers.openstack.services.blockstorage.blockstorage_service import (
    SnapshotResource,
    VolumeResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_blockstorage_snapshot_not_orphaned:
    """Test suite for blockstorage_snapshot_not_orphaned check."""

    def test_no_snapshots(self):
        """Test when no snapshots exist."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.snapshots = []
        blockstorage_client.volumes = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_not_orphaned.blockstorage_snapshot_not_orphaned.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_not_orphaned.blockstorage_snapshot_not_orphaned import (
                blockstorage_snapshot_not_orphaned,
            )

            check = blockstorage_snapshot_not_orphaned()
            result = check.execute()

            assert len(result) == 0

    def test_snapshot_with_existing_volume(self):
        """Test snapshot referencing an existing volume (PASS)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-1",
                name="Existing Volume",
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
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-1",
                name="Valid Snapshot",
                status="available",
                size=100,
                volume_id="vol-1",
                metadata={},
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_not_orphaned.blockstorage_snapshot_not_orphaned.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_not_orphaned.blockstorage_snapshot_not_orphaned import (
                blockstorage_snapshot_not_orphaned,
            )

            check = blockstorage_snapshot_not_orphaned()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Snapshot Valid Snapshot (snap-1) references existing volume vol-1."
            )
            assert result[0].resource_id == "snap-1"
            assert result[0].resource_name == "Valid Snapshot"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_snapshot_orphaned(self):
        """Test snapshot referencing a non-existent volume (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = []
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-2",
                name="Orphaned Snapshot",
                status="available",
                size=100,
                volume_id="vol-deleted",
                metadata={},
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_not_orphaned.blockstorage_snapshot_not_orphaned.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_not_orphaned.blockstorage_snapshot_not_orphaned import (
                blockstorage_snapshot_not_orphaned,
            )

            check = blockstorage_snapshot_not_orphaned()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Snapshot Orphaned Snapshot (snap-2) references non-existent volume vol-deleted and may be orphaned."
            )
            assert result[0].resource_id == "snap-2"
            assert result[0].resource_name == "Orphaned Snapshot"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_snapshots_mixed(self):
        """Test multiple snapshots with mixed orphan status."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-1",
                name="Existing Volume",
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
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-pass",
                name="Pass",
                status="available",
                size=100,
                volume_id="vol-1",
                metadata={},
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
            SnapshotResource(
                id="snap-fail",
                name="Fail",
                status="available",
                size=100,
                volume_id="vol-deleted",
                metadata={},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_not_orphaned.blockstorage_snapshot_not_orphaned.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_not_orphaned.blockstorage_snapshot_not_orphaned import (
                blockstorage_snapshot_not_orphaned,
            )

            check = blockstorage_snapshot_not_orphaned()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
