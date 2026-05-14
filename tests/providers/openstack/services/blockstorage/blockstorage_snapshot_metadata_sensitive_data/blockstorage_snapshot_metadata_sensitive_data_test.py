"""Tests for blockstorage_snapshot_metadata_sensitive_data check."""

from unittest import mock

from prowler.providers.openstack.services.blockstorage.blockstorage_service import (
    SnapshotResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_blockstorage_snapshot_metadata_sensitive_data:
    """Test suite for blockstorage_snapshot_metadata_sensitive_data check."""

    def test_no_snapshots(self):
        """Test when no snapshots exist."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.snapshots = []
        blockstorage_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 0

    def test_snapshot_no_metadata(self):
        """Test snapshot with no metadata (PASS)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-1",
                name="No Metadata",
                status="available",
                size=50,
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Snapshot No Metadata (snap-1) has no metadata (no sensitive data exposure risk)."
            )
            assert result[0].resource_id == "snap-1"
            assert result[0].resource_name == "No Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_snapshot_safe_metadata(self):
        """Test snapshot with safe metadata (PASS)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-2",
                name="Safe Metadata",
                status="available",
                size=50,
                volume_id="vol-1",
                metadata={"environment": "production", "application": "web-app"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Snapshot Safe Metadata (snap-2) metadata does not contain sensitive data."
            )
            assert result[0].resource_id == "snap-2"
            assert result[0].resource_name == "Safe Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_snapshot_password_in_metadata(self):
        """Test snapshot with password in metadata (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-3",
                name="Password Metadata",
                status="available",
                size=50,
                volume_id="vol-1",
                metadata={"db_password": "supersecret123"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "contains potential secrets" in result[0].status_extended

    def test_snapshot_api_key_in_metadata(self):
        """Test snapshot with API key in metadata (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-4",
                name="API Key Metadata",
                status="available",
                size=50,
                volume_id="vol-1",
                metadata={"api_key": "sk-1234567890"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Snapshot API Key Metadata (snap-4) metadata contains potential secrets ->"
            )
            assert result[0].resource_id == "snap-4"
            assert result[0].resource_name == "API Key Metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_snapshot_private_key_in_metadata(self):
        """Test snapshot with private key in metadata (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-5",
                name="Private Key",
                status="available",
                size=50,
                volume_id="vol-1",
                metadata={"ssh_key": "-----BEGIN RSA PRIVATE KEY-----"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Snapshot Private Key (snap-5) metadata contains potential secrets ->"
            )
            assert result[0].resource_id == "snap-5"
            assert result[0].resource_name == "Private Key"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_snapshots_mixed(self):
        """Test multiple snapshots with mixed metadata."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-pass",
                name="Safe",
                status="available",
                size=50,
                volume_id="vol-1",
                metadata={"tier": "web"},
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            ),
            SnapshotResource(
                id="snap-fail",
                name="Unsafe",
                status="available",
                size=50,
                volume_id="vol-2",
                metadata={"admin_password": "secret123"},
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1

    def test_snapshot_metadata_key_correct_identification(self):
        """Test that secrets are correctly attributed to the right metadata keys."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {}
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-6",
                name="Multiple Keys",
                status="available",
                size=50,
                volume_id="vol-1",
                metadata={
                    "environment": "production",
                    "application": "web-app",
                    "db_password": "supersecret123",
                    "region": "us-east",
                },
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
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.blockstorage_client",
                new=blockstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Verify the secret is correctly attributed to 'db_password' key
            assert "in metadata key 'db_password'" in result[0].status_extended
            assert result[0].resource_id == "snap-6"
