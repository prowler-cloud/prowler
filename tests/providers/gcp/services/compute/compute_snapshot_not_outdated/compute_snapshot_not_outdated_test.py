from datetime import datetime, timedelta, timezone
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class TestComputeSnapshotNotOutdated:
    def test_compute_no_snapshots(self):
        compute_client = mock.MagicMock()
        compute_client.snapshots = []
        compute_client.audit_config = {"max_snapshot_age_days": 90}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated import (
                compute_snapshot_not_outdated,
            )

            check = compute_snapshot_not_outdated()
            result = check.execute()
            assert len(result) == 0

    def test_snapshot_within_threshold(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_service import Snapshot
            from prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated import (
                compute_snapshot_not_outdated,
            )

            creation_time = datetime.now(timezone.utc) - timedelta(days=30)

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {"max_snapshot_age_days": 90}
            compute_client.snapshots = [
                Snapshot(
                    name="test-snapshot-recent",
                    id="1234567890",
                    project_id=GCP_PROJECT_ID,
                    creation_timestamp=creation_time,
                    source_disk="test-disk",
                    source_disk_id="disk-123",
                    disk_size_gb=100,
                    storage_bytes=1073741824,
                    storage_locations=["us-central1"],
                    status="READY",
                    auto_created=False,
                )
            ]

            check = compute_snapshot_not_outdated()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "30 days old" in result[0].status_extended
            assert "within the 90 day threshold" in result[0].status_extended
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test-snapshot-recent"
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_snapshot_exceeds_threshold(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_service import Snapshot
            from prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated import (
                compute_snapshot_not_outdated,
            )

            creation_time = datetime.now(timezone.utc) - timedelta(days=120)

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {"max_snapshot_age_days": 90}
            compute_client.snapshots = [
                Snapshot(
                    name="test-snapshot-old",
                    id="0987654321",
                    project_id=GCP_PROJECT_ID,
                    creation_timestamp=creation_time,
                    source_disk="test-disk",
                    source_disk_id="disk-456",
                    disk_size_gb=200,
                    storage_bytes=2147483648,
                    storage_locations=["us-east1"],
                    status="READY",
                    auto_created=False,
                )
            ]

            check = compute_snapshot_not_outdated()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "120 days old" in result[0].status_extended
            assert "exceeding the 90 day threshold" in result[0].status_extended
            assert result[0].resource_id == "0987654321"
            assert result[0].resource_name == "test-snapshot-old"
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_snapshot_no_creation_timestamp(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_service import Snapshot
            from prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated import (
                compute_snapshot_not_outdated,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {"max_snapshot_age_days": 90}
            compute_client.snapshots = [
                Snapshot(
                    name="test-snapshot-no-timestamp",
                    id="1111111111",
                    project_id=GCP_PROJECT_ID,
                    creation_timestamp=None,
                    source_disk="test-disk",
                    source_disk_id="disk-789",
                    disk_size_gb=50,
                    storage_bytes=536870912,
                    storage_locations=["eu-west1"],
                    status="READY",
                    auto_created=False,
                )
            ]

            check = compute_snapshot_not_outdated()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "timestamp could not be retrieved" in result[0].status_extended
            assert result[0].resource_id == "1111111111"
            assert result[0].resource_name == "test-snapshot-no-timestamp"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_snapshots_mixed(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_service import Snapshot
            from prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated import (
                compute_snapshot_not_outdated,
            )

            current_time = datetime.now(timezone.utc)

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {"max_snapshot_age_days": 90}
            compute_client.snapshots = [
                Snapshot(
                    name="recent-snapshot",
                    id="1111111111",
                    project_id=GCP_PROJECT_ID,
                    creation_timestamp=current_time - timedelta(days=10),
                    source_disk="disk-1",
                    status="READY",
                ),
                Snapshot(
                    name="old-snapshot",
                    id="2222222222",
                    project_id=GCP_PROJECT_ID,
                    creation_timestamp=current_time - timedelta(days=150),
                    source_disk="disk-2",
                    status="READY",
                ),
                Snapshot(
                    name="boundary-snapshot",
                    id="3333333333",
                    project_id=GCP_PROJECT_ID,
                    creation_timestamp=current_time - timedelta(days=91),
                    source_disk="disk-3",
                    status="READY",
                ),
            ]

            check = compute_snapshot_not_outdated()
            result = check.execute()

            assert len(result) == 3

            recent_result = next(r for r in result if r.resource_id == "1111111111")
            old_result = next(r for r in result if r.resource_id == "2222222222")
            boundary_result = next(r for r in result if r.resource_id == "3333333333")

            assert recent_result.status == "PASS"
            assert recent_result.resource_name == "recent-snapshot"

            assert old_result.status == "FAIL"
            assert old_result.resource_name == "old-snapshot"

            assert boundary_result.status == "FAIL"
            assert boundary_result.resource_name == "boundary-snapshot"

    def test_custom_threshold(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_service import Snapshot
            from prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated import (
                compute_snapshot_not_outdated,
            )

            creation_time = datetime.now(timezone.utc) - timedelta(days=45)

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {"max_snapshot_age_days": 30}
            compute_client.snapshots = [
                Snapshot(
                    name="test-snapshot-custom",
                    id="4444444444",
                    project_id=GCP_PROJECT_ID,
                    creation_timestamp=creation_time,
                    source_disk="test-disk",
                    status="READY",
                )
            ]

            check = compute_snapshot_not_outdated()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "45 days old" in result[0].status_extended
            assert "exceeding the 30 day threshold" in result[0].status_extended

    def test_default_threshold_when_not_configured(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_service import Snapshot
            from prowler.providers.gcp.services.compute.compute_snapshot_not_outdated.compute_snapshot_not_outdated import (
                compute_snapshot_not_outdated,
            )

            creation_time = datetime.now(timezone.utc) - timedelta(days=85)

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {}
            compute_client.snapshots = [
                Snapshot(
                    name="test-snapshot-default",
                    id="5555555555",
                    project_id=GCP_PROJECT_ID,
                    creation_timestamp=creation_time,
                    source_disk="test-disk",
                    status="READY",
                )
            ]

            check = compute_snapshot_not_outdated()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "85 days old" in result[0].status_extended
            assert "within the 90 day threshold" in result[0].status_extended
