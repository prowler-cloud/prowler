"""Tests for blockstorage_volume_metadata_sensitive_data check."""

from unittest import mock

from prowler.providers.openstack.services.blockstorage.blockstorage_service import (
    VolumeResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_blockstorage_volume_metadata_sensitive_data:
    """Test suite for blockstorage_volume_metadata_sensitive_data check."""

    def test_no_volumes(self):
        """Test when no volumes exist."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.volumes = []
        blockstorage_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data import (
                blockstorage_volume_metadata_sensitive_data,
            )

            check = blockstorage_volume_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 0

    def test_volume_no_metadata(self):
        """Test volume with no metadata (PASS)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-1",
                name="No Metadata",
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data import (
                blockstorage_volume_metadata_sensitive_data,
            )

            check = blockstorage_volume_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Volume No Metadata (vol-1) has no metadata (no sensitive data exposure risk)."
            )
            assert result[0].resource_id == "vol-1"
            assert result[0].resource_name == "No Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_volume_safe_metadata(self):
        """Test volume with safe metadata (PASS)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-2",
                name="Safe Metadata",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={"environment": "production", "application": "web-app"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data import (
                blockstorage_volume_metadata_sensitive_data,
            )

            check = blockstorage_volume_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Volume Safe Metadata (vol-2) metadata does not contain sensitive data."
            )
            assert result[0].resource_id == "vol-2"
            assert result[0].resource_name == "Safe Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_volume_password_in_metadata(self):
        """Test volume with password in metadata (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-3",
                name="Password Metadata",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={"db_password": "supersecret123"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data import (
                blockstorage_volume_metadata_sensitive_data,
            )

            check = blockstorage_volume_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "contains potential secrets" in result[0].status_extended

    def test_volume_api_key_in_metadata(self):
        """Test volume with API key in metadata (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-4",
                name="API Key Metadata",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={"api_key": "sk-1234567890"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data import (
                blockstorage_volume_metadata_sensitive_data,
            )

            check = blockstorage_volume_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Volume API Key Metadata (vol-4) metadata contains potential secrets ->"
            )
            assert result[0].resource_id == "vol-4"
            assert result[0].resource_name == "API Key Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_volume_private_key_in_metadata(self):
        """Test volume with private key in metadata (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-5",
                name="Private Key",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={"ssh_key": "-----BEGIN RSA PRIVATE KEY-----"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data import (
                blockstorage_volume_metadata_sensitive_data,
            )

            check = blockstorage_volume_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Volume Private Key (vol-5) metadata contains potential secrets ->"
            )
            assert result[0].resource_id == "vol-5"
            assert result[0].resource_name == "Private Key"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_volumes_mixed(self):
        """Test multiple volumes with mixed metadata."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-pass",
                name="Safe",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={"tier": "web"},
                availability_zone="nova",
                snapshot_id="",
                source_volume_id="",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
            VolumeResource(
                id="vol-fail",
                name="Unsafe",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={"admin_password": "secret123"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data import (
                blockstorage_volume_metadata_sensitive_data,
            )

            check = blockstorage_volume_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1

    def test_volume_metadata_key_correct_identification(self):
        """Test that secrets are correctly attributed to the right metadata keys."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.volumes = [
            VolumeResource(
                id="vol-6",
                name="Multiple Keys",
                status="in-use",
                size=100,
                volume_type="standard",
                is_encrypted=False,
                is_bootable=False,
                is_multiattach=False,
                attachments=[],
                metadata={
                    "environment": "production",
                    "application": "web-app",
                    "db_password": "supersecret123",
                    "region": "us-east",
                },
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_volume_metadata_sensitive_data.blockstorage_volume_metadata_sensitive_data import (
                blockstorage_volume_metadata_sensitive_data,
            )

            check = blockstorage_volume_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Verify the secret is correctly attributed to 'db_password' key
            assert "in metadata key 'db_password'" in result[0].status_extended
            assert result[0].resource_id == "vol-6"
