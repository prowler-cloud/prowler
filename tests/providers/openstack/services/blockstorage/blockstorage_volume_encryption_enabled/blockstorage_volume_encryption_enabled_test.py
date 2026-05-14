"""Tests for blockstorage_volume_encryption_enabled check."""

from unittest import mock

from prowler.providers.openstack.services.blockstorage.blockstorage_service import (
    VolumeResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_blockstorage_volume_encryption_enabled:
    """Test suite for blockstorage_volume_encryption_enabled check."""

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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_encryption_enabled.blockstorage_volume_encryption_enabled.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_encryption_enabled.blockstorage_volume_encryption_enabled import (
                blockstorage_volume_encryption_enabled,
            )

            check = blockstorage_volume_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_volume_encrypted(self):
        """Test volume with encryption enabled (PASS)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-1",
                name="Encrypted Volume",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=True,
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_encryption_enabled.blockstorage_volume_encryption_enabled.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_encryption_enabled.blockstorage_volume_encryption_enabled import (
                blockstorage_volume_encryption_enabled,
            )

            check = blockstorage_volume_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Volume Encrypted Volume (vol-1) has encryption enabled."
            )
            assert result[0].resource_id == "vol-1"
            assert result[0].resource_name == "Encrypted Volume"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_volume_not_encrypted(self):
        """Test volume without encryption (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-2",
                name="Unencrypted Volume",
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_encryption_enabled.blockstorage_volume_encryption_enabled.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_encryption_enabled.blockstorage_volume_encryption_enabled import (
                blockstorage_volume_encryption_enabled,
            )

            check = blockstorage_volume_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Volume Unencrypted Volume (vol-2) does not have encryption enabled."
            )
            assert result[0].resource_id == "vol-2"
            assert result[0].resource_name == "Unencrypted Volume"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_volumes_mixed(self):
        """Test multiple volumes with mixed encryption status."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-pass",
                name="Pass",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=True,
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_encryption_enabled.blockstorage_volume_encryption_enabled.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_encryption_enabled.blockstorage_volume_encryption_enabled import (
                blockstorage_volume_encryption_enabled,
            )

            check = blockstorage_volume_encryption_enabled()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
