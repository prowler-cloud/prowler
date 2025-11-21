from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

from api.models import (
    AttackPathsScan,
    Finding,
    Provider,
    Resource,
    ResourceFindingMapping,
    Scan,
    StateChoices,
    StatusChoices,
)
from prowler.lib.check.models import Severity
from tasks.jobs.attack_paths import prowler as prowler_module
from tasks.jobs.attack_paths.scan import run as attack_paths_run


@pytest.mark.django_db
class TestAttackPathsRun:
    def test_run_success_flow(self, tenants_fixture, providers_fixture, scans_fixture):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()
        scan = scans_fixture[0]
        scan.provider = provider
        scan.save()

        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.SCHEDULED,
        )

        mock_session = MagicMock()
        session_ctx = MagicMock()
        session_ctx.__enter__.return_value = mock_session
        session_ctx.__exit__.return_value = False
        ingestion_result = {"organizations": "warning"}
        ingestion_fn = MagicMock(return_value=ingestion_result)

        with (
            patch(
                "tasks.jobs.attack_paths.scan.rls_transaction",
                new=lambda *args, **kwargs: nullcontext(),
            ),
            patch(
                "tasks.jobs.attack_paths.scan.initialize_prowler_provider",
                return_value=MagicMock(_enabled_regions=["us-east-1"]),
            ),
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_uri",
                return_value="bolt://neo4j",
            ),
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_tenant_database_name",
                return_value="tenant-db",
            ) as mock_get_db_name,
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.create_database"
            ) as mock_create_db,
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_session",
                return_value=session_ctx,
            ) as mock_get_session,
            patch(
                "tasks.jobs.attack_paths.scan.cartography_create_indexes.run"
            ) as mock_cartography_indexes,
            patch(
                "tasks.jobs.attack_paths.scan.cartography_analysis.run"
            ) as mock_cartography_analysis,
            patch(
                "tasks.jobs.attack_paths.scan.prowler.create_indexes"
            ) as mock_prowler_indexes,
            patch(
                "tasks.jobs.attack_paths.scan.prowler.analysis"
            ) as mock_prowler_analysis,
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ) as mock_retrieve_scan,
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.starting_attack_paths_scan"
            ) as mock_starting,
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.update_attack_paths_scan_progress"
            ) as mock_update_progress,
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.finish_attack_paths_scan"
            ) as mock_finish,
            patch(
                "tasks.jobs.attack_paths.scan.get_cartography_ingestion_function",
                return_value=ingestion_fn,
            ) as mock_get_ingestion,
            patch(
                "tasks.jobs.attack_paths.scan._call_within_event_loop",
                side_effect=lambda fn, *a, **kw: fn(*a, **kw),
            ) as mock_event_loop,
        ):
            result = attack_paths_run(str(tenant.id), str(scan.id), "task-123")

        assert result == ingestion_result
        mock_retrieve_scan.assert_called_once_with(str(tenant.id), str(scan.id))
        mock_starting.assert_called_once()
        config = mock_starting.call_args[0][2]
        assert config.neo4j_database == "tenant-db"

        mock_create_db.assert_called_once_with("tenant-db")
        mock_get_session.assert_called_once_with("tenant-db")
        mock_cartography_indexes.assert_called_once_with(mock_session, config)
        mock_prowler_indexes.assert_called_once_with(mock_session)
        mock_cartography_analysis.assert_called_once_with(mock_session, config)
        mock_prowler_analysis.assert_called_once_with(mock_session, provider, config)
        assert mock_get_ingestion.call_args_list == [
            call(provider.provider),
            call(provider.provider),
        ]
        mock_event_loop.assert_called_once()
        mock_update_progress.assert_any_call(attack_paths_scan, 1)
        mock_update_progress.assert_any_call(attack_paths_scan, 2)
        mock_update_progress.assert_any_call(attack_paths_scan, 95)
        mock_finish.assert_called_once_with(
            attack_paths_scan, StateChoices.COMPLETED, ingestion_result
        )
        mock_get_db_name.assert_called_once_with(str(provider.tenant_id))

    def test_run_failure_marks_scan_failed(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()
        scan = scans_fixture[0]
        scan.provider = provider
        scan.save()

        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.SCHEDULED,
        )

        mock_session = MagicMock()
        session_ctx = MagicMock()
        session_ctx.__enter__.return_value = mock_session
        session_ctx.__exit__.return_value = False
        ingestion_fn = MagicMock(side_effect=RuntimeError("ingestion boom"))

        with (
            patch(
                "tasks.jobs.attack_paths.scan.rls_transaction",
                new=lambda *args, **kwargs: nullcontext(),
            ),
            patch(
                "tasks.jobs.attack_paths.scan.initialize_prowler_provider",
                return_value=MagicMock(_enabled_regions=["us-east-1"]),
            ),
            patch("tasks.jobs.attack_paths.scan.graph_database.get_uri"),
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_tenant_database_name",
                return_value="tenant-db",
            ),
            patch("tasks.jobs.attack_paths.scan.graph_database.create_database"),
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_session",
                return_value=session_ctx,
            ),
            patch("tasks.jobs.attack_paths.scan.cartography_create_indexes.run"),
            patch("tasks.jobs.attack_paths.scan.cartography_analysis.run"),
            patch("tasks.jobs.attack_paths.scan.prowler.create_indexes"),
            patch("tasks.jobs.attack_paths.scan.prowler.analysis"),
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ),
            patch("tasks.jobs.attack_paths.scan.db_utils.starting_attack_paths_scan"),
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.update_attack_paths_scan_progress"
            ),
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.finish_attack_paths_scan"
            ) as mock_finish,
            patch(
                "tasks.jobs.attack_paths.scan.get_cartography_ingestion_function",
                return_value=ingestion_fn,
            ),
            patch(
                "tasks.jobs.attack_paths.scan._call_within_event_loop",
                side_effect=lambda fn, *a, **kw: fn(*a, **kw),
            ),
            patch(
                "tasks.jobs.attack_paths.scan.utils.stringify_exception",
                return_value="Cartography failed: ingestion boom",
            ),
        ):
            with pytest.raises(RuntimeError, match="ingestion boom"):
                attack_paths_run(str(tenant.id), str(scan.id), "task-456")

        failure_args = mock_finish.call_args[0]
        assert failure_args[0] is attack_paths_scan
        assert failure_args[1] == StateChoices.FAILED
        assert failure_args[2] == {
            "global_cartography_error": "Cartography failed: ingestion boom"
        }

    def test_run_returns_early_for_unsupported_provider(self, tenants_fixture):
        tenant = tenants_fixture[0]
        provider = Provider.objects.create(
            provider=Provider.ProviderChoices.GCP,
            uid="gcp-account",
            alias="gcp",
            tenant_id=tenant.id,
        )
        scan = Scan.objects.create(
            name="GCP Scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            tenant_id=tenant.id,
        )

        with (
            patch(
                "tasks.jobs.attack_paths.scan.rls_transaction",
                new=lambda *args, **kwargs: nullcontext(),
            ),
            patch(
                "tasks.jobs.attack_paths.scan.initialize_prowler_provider",
                return_value=MagicMock(),
            ),
            patch(
                "tasks.jobs.attack_paths.scan.get_cartography_ingestion_function",
                return_value=None,
            ) as mock_get_ingestion,
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.retrieve_attack_paths_scan"
            ) as mock_retrieve,
        ):
            result = attack_paths_run(str(tenant.id), str(scan.id), "task-789")

        assert result == {}
        mock_get_ingestion.assert_called_once_with(provider.provider)
        mock_retrieve.assert_not_called()


@pytest.mark.django_db
class TestAttackPathsProwlerHelpers:
    def test_create_indexes_executes_all_statements(self):
        mock_session = MagicMock()
        with patch("tasks.jobs.attack_paths.prowler.run_write_query") as mock_run_write:
            prowler_module.create_indexes(mock_session)

        assert mock_run_write.call_count == len(prowler_module.INDEX_STATEMENTS)
        mock_run_write.assert_has_calls(
            [call(mock_session, stmt) for stmt in prowler_module.INDEX_STATEMENTS]
        )

    def test_load_findings_batches_requests(self, providers_fixture):
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()

        findings = [
            {"id": "1", "resource_uid": "r-1"},
            {"id": "2", "resource_uid": "r-2"},
        ]
        config = SimpleNamespace(update_tag=12345)
        mock_session = MagicMock()

        with (
            patch.object(prowler_module, "BATCH_SIZE", 1),
            patch(
                "tasks.jobs.attack_paths.prowler.get_root_node_label",
                return_value="AWSAccount",
            ),
            patch(
                "tasks.jobs.attack_paths.prowler.get_node_uid_field",
                return_value="arn",
            ),
        ):
            prowler_module.load_findings(mock_session, findings, provider, config)

        assert mock_session.run.call_count == 2
        for call_args in mock_session.run.call_args_list:
            params = call_args.args[1]
            assert params["provider_uid"] == str(provider.uid)
            assert params["last_updated"] == config.update_tag
            assert "findings_data" in params

    def test_cleanup_findings_runs_batches(self, providers_fixture):
        provider = providers_fixture[0]
        config = SimpleNamespace(update_tag=1024)
        mock_session = MagicMock()

        first_batch = MagicMock()
        first_batch.single.return_value = {"deleted_findings_count": 3}
        second_batch = MagicMock()
        second_batch.single.return_value = {"deleted_findings_count": 0}
        mock_session.run.side_effect = [first_batch, second_batch]

        prowler_module.cleanup_findings(mock_session, provider, config)

        assert mock_session.run.call_count == 2
        params = mock_session.run.call_args.args[1]
        assert params["provider_uid"] == str(provider.uid)
        assert params["last_updated"] == config.update_tag

    def test_get_provider_last_scan_findings_returns_latest_scan_data(
        self,
        tenants_fixture,
        providers_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()

        resource = Resource.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            uid="resource-uid",
            name="Resource",
            region="us-east-1",
            service="ec2",
            type="instance",
        )

        older_scan = Scan.objects.create(
            name="Older",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant_id=tenant.id,
        )
        old_finding = Finding.objects.create(
            tenant_id=tenant.id,
            uid="older-finding",
            scan=older_scan,
            delta=Finding.DeltaChoices.NEW,
            status=StatusChoices.PASS,
            status_extended="ok",
            severity=Severity.low,
            impact=Severity.low,
            impact_extended="",
            raw_result={},
            check_id="check-old",
            check_metadata={"checktitle": "Old"},
            first_seen_at=older_scan.inserted_at,
        )
        ResourceFindingMapping.objects.create(
            tenant_id=tenant.id,
            resource=resource,
            finding=old_finding,
        )

        latest_scan = Scan.objects.create(
            name="Latest",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant_id=tenant.id,
        )
        finding = Finding.objects.create(
            tenant_id=tenant.id,
            uid="finding-uid",
            scan=latest_scan,
            delta=Finding.DeltaChoices.NEW,
            status=StatusChoices.FAIL,
            status_extended="failed",
            severity=Severity.high,
            impact=Severity.high,
            impact_extended="",
            raw_result={},
            check_id="check-1",
            check_metadata={"checktitle": "Check title"},
            first_seen_at=latest_scan.inserted_at,
        )
        ResourceFindingMapping.objects.create(
            tenant_id=tenant.id,
            resource=resource,
            finding=finding,
        )

        latest_scan.refresh_from_db()

        with patch(
            "tasks.jobs.attack_paths.prowler.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            findings_data = prowler_module.get_provider_last_scan_findings(provider)

        assert len(findings_data) == 1
        finding_dict = findings_data[0]
        assert finding_dict["id"] == str(finding.id)
        assert finding_dict["resource_uid"] == resource.uid
        assert finding_dict["check_title"] == "Check title"
        assert finding_dict["scan_id"] == str(latest_scan.id)
