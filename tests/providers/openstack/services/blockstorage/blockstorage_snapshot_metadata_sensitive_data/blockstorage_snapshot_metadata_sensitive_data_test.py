"""Tests for blockstorage_snapshot_metadata_sensitive_data check."""

from unittest import mock

from prowler.lib.check.models import Severity
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
                metadata={"db_password": "Tr0ub4dor3xKq9vLmZ"},
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
                metadata={
                    "api_key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
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
                metadata={
                    "ssh_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCUzlT9QGi8ZSr5\nk+LTRz/1TaiCCs6o1icW4cur0Q0hdBnbRJXUdjlQsgzmBvCBNkGHI8hb/RUPssvc\nDLU5kOQ3Wp2KgtbphhZ2PfpuJrzwHL1ejcJkRxegm/aTdmpoQKcxGeehAfHbmlLA\nxdfn6wPDfGji973yiRH56JRukJAaqF50HC2a/AVNC5HtZoVlbQ+WvVbYVUnPxNkv\nPpc53PjrBgWiTtdMONEqJ3jDiaqfUBt+TZYF0CFc9HgjnUniRX28OukDyLu+idOz\nFKyZxMXtqexkAvQLDW1PATpZgVQ7hJoCD8UVTXAtcgzPq5fA6AR2URiECHI6ZyL0\nUmixKfMNAgMBAAECggEAJRzp5wjdpmEgDQOkjpfGXJ6sAJUD8mmI8cTKeJWIzhdo\nDH8oVEdRJ65kl6lS6hMXWEZlJgYyrsnj3MPBnjQkKycbRCy6P59s8jwmfbsFI+iz\nFUZLXZm6i5jicGhYBRzc5hrlIYu73863RXOClAnSFDsu6K6rzfYASQFIJeRBwJfs\njqXinuun/h2zGjpiY+TtNsa8c+nC7f3sGsTzNJugDvBPWQzsnAMzXJqiyharre4V\no157XIOvdC0joIp8j/Ib1ZtMfz1K1LcgBgw0szSieIw0Rq8yQ0Ek7GtLh43jG+ap\nvcSEesTD1p4mjPXoWkPG8KYd4iwGedZaePfheVcKKQKBgQDNE03SWv18AH0d4fpB\nlFAtRybCfSvMORzBrt2oilz8wDmK+Zga5o+phCnM8v3eJy1v8BvIQ9RvwQA2uVgZ\nr701wNMpVrTsMujk83oVRhimZLk6Hyw07wmMgEHX7+izkm2Lk4Lk7Zol3VRfnWG6\nmIcUk7xB1yAs3mudsfx0VO0QyQKBgQC5wfdqCLj2hZk4sMZu8Bth+BHKChGItmDk\nAW7aNt+gaPyoryOJoi2OUO8ud8EyuqXiuslSk2pPtjvLhCppkoq6V8kmPAUzaxFk\n4nDEAxT9Un8IJ0j2ebv+koQKsBWjssbVSjrZgIcYIDK1QblgbCp2FSE3ima+V8ip\nOdNjiatWJQKBgEX8lox5nRSanhh6rIuA8DPjmmi5ix7xRs0avm7seXuQppK1R6G2\nmcTCY/mb2+Pa/vi6uuCHtZJGDaqfal+pyCr2GZp8CtapMS4hocJs37C5ozUguld+\nVIXsp4voRkQybsw5lWxHYloVxNu0vEuQDlmJabAWmNZ3OcbhnUSeTyFxAoGAFtkZ\n0owCHChwoT11Gt4jsBgwL/avE27DWigm92Y6eWOQeDsalupAyjmAQenu9Itqrgml\ni6egMu/KSQ0Xnmas86CqmC5XwWxQ9mS31BRA96u2/ky+t7pfej+RSDNCZiEuPbvk\noy4g78G+GvdbktWbH20X6dn3K0Bm6RG4w4yCa5UCgYBs0zAVs0DZmM8SUZJA/HuQ\nN6a1vKKns7xKw5N3SmX1KbDhx5LSZXfbUo2+QktE7iRf9G2f1o0q8kz9l/4AGXi1\nKJNUHupWoaQzGNrzAb27TUtFA0ocMG8KnqxjANWox5oPJS9OU5tw5H5dxeI/Senc\nkYW6eCnRzPcmBqex6Vuw4w==\n-----END PRIVATE KEY-----\n"
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
                metadata={"admin_password": "Tr0ub4dor3xKq9vLmZ"},
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
                    "db_password": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
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

    def test_snapshot_verified_secret_escalates_to_critical(self):
        """Test that a confirmed live secret escalates the finding to CRITICAL (FAIL)."""
        blockstorage_client = mock.MagicMock()
        blockstorage_client.audit_config = {"secrets_validate": True}
        blockstorage_client.snapshots = [
            SnapshotResource(
                id="snap-verified",
                name="Verified Secret",
                status="available",
                size=50,
                volume_id="vol-1",
                metadata={"api_key": "placeholder"},
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
            mock.patch(
                "prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data.detect_secrets_scan_batch",
                return_value={
                    0: [
                        {
                            "type": "JSON Web Token (base64url-encoded)",
                            "line_number": 2,
                            "filename": "data",
                            "hashed_secret": "x",
                            "is_verified": True,
                        }
                    ]
                },
            ) as mock_scan,
        ):
            from prowler.providers.openstack.services.blockstorage.blockstorage_snapshot_metadata_sensitive_data.blockstorage_snapshot_metadata_sensitive_data import (
                blockstorage_snapshot_metadata_sensitive_data,
            )

            check = blockstorage_snapshot_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.critical
            assert "confirmed to be live" in result[0].status_extended
            assert mock_scan.call_args.kwargs.get("validate") is True
