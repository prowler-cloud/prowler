"""Tests for blockstorage_volume_not_unattached check."""

from unittest import mock

from prowler.providers.openstack.services.blockstorage.blockstorage_service import (
    VolumeResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_blockstorage_volume_not_unattached:
    """Test suite for blockstorage_volume_not_unattached check."""

    def test_no_volumes(self):
        """Test when no volumes exist."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached import (
                blockstorage_volume_not_unattached,
            )

            check = blockstorage_volume_not_unattached()
            result = check.execute()

            assert len(result) == 0

    def test_volume_attached(self):
        """Test volume that is attached to instances (PASS)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-1",
                name="Attached Volume",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[
                    {"server_id": "server-1"},
                    {"server_id": "server-2"},
                ],
                metadata={},
                availability_zone="nova",
                snapshot_id="",
                source_volume_id="",
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached import (
                blockstorage_volume_not_unattached,
            )

            check = blockstorage_volume_not_unattached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Volume Attached Volume (vol-1) is attached to 2 instance(s)."
            )
            assert result[0].resource_id == "vol-1"
            assert result[0].resource_name == "Attached Volume"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_volume_unattached_available(self):
        """Test volume that is available and unattached (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-2",
                name="Orphaned Volume",
                status="available",
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached import (
                blockstorage_volume_not_unattached,
            )

            check = blockstorage_volume_not_unattached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Volume Orphaned Volume (vol-2) is unattached and may be orphaned."
            )
            assert result[0].resource_id == "vol-2"
            assert result[0].resource_name == "Orphaned Volume"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_volume_unattached_non_available_status(self):
        """Test volume that is unattached but in non-available state (PASS - not idle)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-3",
                name="Error Volume",
                status="error",
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached import (
                blockstorage_volume_not_unattached,
            )

            check = blockstorage_volume_not_unattached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "'error' state (not idle)" in result[0].status_extended

    def test_multiple_volumes_mixed(self):
        """Test multiple volumes with mixed attachment status."""
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
                attachments=[{"server_id": "server-1"}],
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
                status="available",
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_not_unattached.blockstorage_volume_not_unattached import (
                blockstorage_volume_not_unattached,
            )

            check = blockstorage_volume_not_unattached()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
