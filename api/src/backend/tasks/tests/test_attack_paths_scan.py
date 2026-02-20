from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest
from tasks.jobs.attack_paths import findings as findings_module
from tasks.jobs.attack_paths import internet as internet_module
from tasks.jobs.attack_paths import sync as sync_module
from tasks.jobs.attack_paths.config import (
    get_deprecated_provider_resource_label,
)
from tasks.jobs.attack_paths.scan import run as attack_paths_run

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


@pytest.mark.django_db
class TestAttackPathsRun:
    # Patching with decorators as we got a `SyntaxError: too many statically nested blocks` error if we use context managers
    @patch("tasks.jobs.attack_paths.scan.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.scan.utils.call_within_event_loop",
        side_effect=lambda fn, *a, **kw: fn(*a, **kw),
    )
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_provider_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.finish_attack_paths_scan")
    @patch("tasks.jobs.attack_paths.scan.db_utils.update_attack_paths_scan_progress")
    @patch("tasks.jobs.attack_paths.scan.db_utils.starting_attack_paths_scan")
    @patch("tasks.jobs.attack_paths.scan.sync.sync_graph")
    @patch("tasks.jobs.attack_paths.scan.graph_database.drop_subgraph")
    @patch("tasks.jobs.attack_paths.scan.sync.create_sync_indexes")
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_ontology.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.clear_cache")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_uri",
        return_value="bolt://neo4j",
    )
    @patch(
        "tasks.jobs.attack_paths.scan.initialize_prowler_provider",
        return_value=MagicMock(_enabled_regions=["us-east-1"]),
    )
    @patch(
        "tasks.jobs.attack_paths.scan.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    def test_run_success_flow(
        self,
        mock_init_provider,
        mock_get_uri,
        mock_create_db,
        mock_clear_cache,
        mock_cartography_indexes,
        mock_cartography_analysis,
        mock_cartography_ontology,
        mock_findings_indexes,
        mock_findings_analysis,
        mock_internet_analysis,
        mock_sync_indexes,
        mock_drop_subgraph,
        mock_sync,
        mock_starting,
        mock_update_progress,
        mock_finish,
        mock_set_provider_graph_data_ready,
        mock_set_graph_data_ready,
        mock_event_loop,
        mock_drop_db,
        tenants_fixture,
        providers_fixture,
        scans_fixture,
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
        ingestion_result = {"organizations": "warning"}
        ingestion_fn = MagicMock(return_value=ingestion_result)

        with (
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
                side_effect=["db-scan-id", "tenant-db"],
            ) as mock_get_db_name,
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_session",
                return_value=session_ctx,
            ) as mock_get_session,
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ) as mock_retrieve_scan,
            patch(
                "tasks.jobs.attack_paths.scan.get_cartography_ingestion_function",
                return_value=ingestion_fn,
            ) as mock_get_ingestion,
        ):
            result = attack_paths_run(str(tenant.id), str(scan.id), "task-123")

        assert result == ingestion_result
        mock_retrieve_scan.assert_called_once_with(str(tenant.id), str(scan.id))
        mock_starting.assert_called_once()
        config = mock_starting.call_args[0][2]
        assert config.neo4j_database == "tenant-db"
        mock_get_db_name.assert_has_calls(
            [call(attack_paths_scan.id, temporary=True), call(provider.tenant_id)]
        )

        mock_create_db.assert_has_calls([call("db-scan-id"), call("tenant-db")])
        mock_get_session.assert_has_calls([call("db-scan-id"), call("tenant-db")])
        assert mock_cartography_indexes.call_count == 2
        mock_findings_indexes.assert_has_calls([call(mock_session), call(mock_session)])
        mock_sync_indexes.assert_called_once_with(mock_session)
        # These use tmp_cartography_config (neo4j_database="db-scan-id")
        mock_cartography_analysis.assert_called_once()
        mock_cartography_ontology.assert_called_once()
        mock_internet_analysis.assert_called_once()
        mock_findings_analysis.assert_called_once()
        mock_drop_subgraph.assert_called_once_with(
            database="tenant-db",
            provider_id=str(provider.id),
        )
        mock_sync.assert_called_once_with(
            source_database="db-scan-id",
            target_database="tenant-db",
            provider_id=str(provider.id),
        )
        mock_get_ingestion.assert_called_once_with(provider.provider)
        mock_event_loop.assert_called_once()
        mock_update_progress.assert_any_call(attack_paths_scan, 1)
        mock_update_progress.assert_any_call(attack_paths_scan, 2)
        mock_update_progress.assert_any_call(attack_paths_scan, 95)
        mock_update_progress.assert_any_call(attack_paths_scan, 97)
        mock_update_progress.assert_any_call(attack_paths_scan, 98)
        mock_update_progress.assert_any_call(attack_paths_scan, 99)
        mock_finish.assert_called_once_with(
            attack_paths_scan, StateChoices.COMPLETED, ingestion_result
        )
        mock_set_provider_graph_data_ready.assert_called_once_with(
            attack_paths_scan, False
        )
        mock_set_graph_data_ready.assert_called_once_with(attack_paths_scan, True)

    @patch(
        "tasks.jobs.attack_paths.scan.utils.stringify_exception",
        return_value="Cartography failed: ingestion boom",
    )
    @patch(
        "tasks.jobs.attack_paths.scan.utils.call_within_event_loop",
        side_effect=lambda fn, *a, **kw: fn(*a, **kw),
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.scan.db_utils.finish_attack_paths_scan")
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_provider_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.update_attack_paths_scan_progress")
    @patch("tasks.jobs.attack_paths.scan.db_utils.starting_attack_paths_scan")
    @patch("tasks.jobs.attack_paths.scan.findings.analysis")
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
        return_value="db-scan-id",
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.get_uri")
    @patch(
        "tasks.jobs.attack_paths.scan.initialize_prowler_provider",
        return_value=MagicMock(_enabled_regions=["us-east-1"]),
    )
    @patch(
        "tasks.jobs.attack_paths.scan.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    def test_run_failure_marks_scan_failed(
        self,
        mock_init_provider,
        mock_get_uri,
        mock_get_db_name,
        mock_create_db,
        mock_cartography_indexes,
        mock_cartography_analysis,
        mock_findings_indexes,
        mock_internet_analysis,
        mock_findings_analysis,
        mock_starting,
        mock_update_progress,
        mock_set_provider_graph_data_ready,
        mock_set_graph_data_ready,
        mock_finish,
        mock_drop_db,
        mock_event_loop,
        mock_stringify,
        tenants_fixture,
        providers_fixture,
        scans_fixture,
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
                "tasks.jobs.attack_paths.scan.graph_database.get_session",
                return_value=session_ctx,
            ),
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ),
            patch(
                "tasks.jobs.attack_paths.scan.get_cartography_ingestion_function",
                return_value=ingestion_fn,
            ),
        ):
            with pytest.raises(RuntimeError, match="ingestion boom"):
                attack_paths_run(str(tenant.id), str(scan.id), "task-456")

        failure_args = mock_finish.call_args[0]
        assert failure_args[0] is attack_paths_scan
        assert failure_args[1] == StateChoices.FAILED
        assert failure_args[2] == {"global_error": "Cartography failed: ingestion boom"}

    @patch(
        "tasks.jobs.attack_paths.scan.utils.stringify_exception",
        return_value="Cartography failed: ingestion boom",
    )
    @patch(
        "tasks.jobs.attack_paths.scan.utils.call_within_event_loop",
        side_effect=lambda fn, *a, **kw: fn(*a, **kw),
    )
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.drop_database",
        side_effect=ConnectionError("neo4j down"),
    )
    @patch("tasks.jobs.attack_paths.scan.db_utils.finish_attack_paths_scan")
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_provider_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.update_attack_paths_scan_progress")
    @patch("tasks.jobs.attack_paths.scan.db_utils.starting_attack_paths_scan")
    @patch("tasks.jobs.attack_paths.scan.findings.analysis")
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
        return_value="db-scan-id",
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.get_uri")
    @patch(
        "tasks.jobs.attack_paths.scan.initialize_prowler_provider",
        return_value=MagicMock(_enabled_regions=["us-east-1"]),
    )
    @patch(
        "tasks.jobs.attack_paths.scan.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    def test_run_failure_marks_scan_failed_even_when_drop_database_fails(
        self,
        mock_init_provider,
        mock_get_uri,
        mock_get_db_name,
        mock_create_db,
        mock_cartography_indexes,
        mock_cartography_analysis,
        mock_findings_indexes,
        mock_internet_analysis,
        mock_findings_analysis,
        mock_starting,
        mock_update_progress,
        mock_set_provider_graph_data_ready,
        mock_set_graph_data_ready,
        mock_finish,
        mock_drop_db,
        mock_event_loop,
        mock_stringify,
        tenants_fixture,
        providers_fixture,
        scans_fixture,
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
                "tasks.jobs.attack_paths.scan.graph_database.get_session",
                return_value=session_ctx,
            ),
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ),
            patch(
                "tasks.jobs.attack_paths.scan.get_cartography_ingestion_function",
                return_value=ingestion_fn,
            ),
        ):
            with pytest.raises(RuntimeError, match="ingestion boom"):
                attack_paths_run(str(tenant.id), str(scan.id), "task-789")

        failure_args = mock_finish.call_args[0]
        assert failure_args[0] is attack_paths_scan
        assert failure_args[1] == StateChoices.FAILED
        assert failure_args[2] == {"global_error": "Cartography failed: ingestion boom"}

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
            mock_retrieve.return_value = None
            result = attack_paths_run(str(tenant.id), str(scan.id), "task-789")

        assert result == {
            "global_error": "Provider gcp is not supported for Attack Paths scans"
        }
        mock_get_ingestion.assert_called_once_with(provider.provider)
        mock_retrieve.assert_called_once_with(str(tenant.id), str(scan.id))


@pytest.mark.django_db
class TestFailAttackPathsScan:
    def test_marks_executing_scan_as_failed(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import (
            fail_attack_paths_scan,
        )

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
            state=StateChoices.EXECUTING,
        )

        with (
            patch(
                "tasks.jobs.attack_paths.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ) as mock_retrieve,
            patch(
                "tasks.jobs.attack_paths.db_utils.graph_database.drop_database"
            ) as mock_drop_db,
            patch(
                "tasks.jobs.attack_paths.db_utils.finish_attack_paths_scan"
            ) as mock_finish,
        ):
            fail_attack_paths_scan(str(tenant.id), str(scan.id), "setup exploded")

        mock_retrieve.assert_called_once_with(str(tenant.id), str(scan.id))
        expected_tmp_db = f"db-tmp-scan-{str(attack_paths_scan.id).lower()}"
        mock_drop_db.assert_called_once_with(expected_tmp_db)
        mock_finish.assert_called_once_with(
            attack_paths_scan,
            StateChoices.FAILED,
            {"global_error": "setup exploded"},
        )

    def test_drops_temp_database_even_when_drop_fails(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import (
            fail_attack_paths_scan,
        )

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
            state=StateChoices.EXECUTING,
        )

        with (
            patch(
                "tasks.jobs.attack_paths.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ),
            patch(
                "tasks.jobs.attack_paths.db_utils.graph_database.drop_database",
                side_effect=Exception("Neo4j unreachable"),
            ),
            patch(
                "tasks.jobs.attack_paths.db_utils.finish_attack_paths_scan"
            ) as mock_finish,
        ):
            fail_attack_paths_scan(str(tenant.id), str(scan.id), "setup exploded")

        mock_finish.assert_called_once_with(
            attack_paths_scan,
            StateChoices.FAILED,
            {"global_error": "setup exploded"},
        )

    def test_skips_already_failed_scan(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import (
            fail_attack_paths_scan,
        )

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
            state=StateChoices.FAILED,
        )

        with (
            patch(
                "tasks.jobs.attack_paths.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ),
            patch(
                "tasks.jobs.attack_paths.db_utils.graph_database.drop_database"
            ) as mock_drop_db,
            patch(
                "tasks.jobs.attack_paths.db_utils.finish_attack_paths_scan"
            ) as mock_finish,
        ):
            fail_attack_paths_scan(str(tenant.id), str(scan.id), "setup exploded")

        mock_drop_db.assert_not_called()
        mock_finish.assert_not_called()

    def test_skips_when_no_scan_found(self, tenants_fixture):
        from tasks.jobs.attack_paths.db_utils import (
            fail_attack_paths_scan,
        )

        tenant = tenants_fixture[0]

        with (
            patch(
                "tasks.jobs.attack_paths.db_utils.retrieve_attack_paths_scan",
                return_value=None,
            ),
            patch(
                "tasks.jobs.attack_paths.db_utils.finish_attack_paths_scan"
            ) as mock_finish,
        ):
            fail_attack_paths_scan(str(tenant.id), "nonexistent", "setup exploded")

        mock_finish.assert_not_called()


class TestAttackPathsScanRLSTaskOnFailure:
    def test_on_failure_delegates_to_fail_attack_paths_scan(self):
        from tasks.tasks import AttackPathsScanRLSTask

        task = AttackPathsScanRLSTask()

        with patch(
            "tasks.tasks.attack_paths_db_utils.fail_attack_paths_scan"
        ) as mock_fail:
            task.on_failure(
                exc=RuntimeError("boom"),
                task_id="task-abc",
                args=(),
                kwargs={"tenant_id": "t-1", "scan_id": "s-1"},
                _einfo=None,
            )

        mock_fail.assert_called_once_with("t-1", "s-1", "boom")

    def test_on_failure_skips_when_missing_kwargs(self):
        from tasks.tasks import AttackPathsScanRLSTask

        task = AttackPathsScanRLSTask()

        with patch(
            "tasks.tasks.attack_paths_db_utils.fail_attack_paths_scan"
        ) as mock_fail:
            task.on_failure(
                exc=RuntimeError("boom"),
                task_id="task-abc",
                args=(),
                kwargs={},
                _einfo=None,
            )

        mock_fail.assert_not_called()


@pytest.mark.django_db
class TestAttackPathsFindingsHelpers:
    def test_create_findings_indexes_executes_all_statements(self):
        mock_session = MagicMock()
        with patch("tasks.jobs.attack_paths.indexes.run_write_query") as mock_run_write:
            findings_module.create_findings_indexes(mock_session)

        from tasks.jobs.attack_paths.indexes import FINDINGS_INDEX_STATEMENTS

        assert mock_run_write.call_count == len(FINDINGS_INDEX_STATEMENTS)
        mock_run_write.assert_has_calls(
            [call(mock_session, stmt) for stmt in FINDINGS_INDEX_STATEMENTS]
        )

    def test_load_findings_batches_requests(self, providers_fixture):
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()

        # Create mock Finding objects with to_dict() method
        mock_finding_1 = MagicMock()
        mock_finding_1.to_dict.return_value = {"id": "1", "resource_uid": "r-1"}
        mock_finding_2 = MagicMock()
        mock_finding_2.to_dict.return_value = {"id": "2", "resource_uid": "r-2"}

        # Create a generator that yields two batches of Finding instances
        def findings_generator():
            yield [mock_finding_1]
            yield [mock_finding_2]

        config = SimpleNamespace(update_tag=12345)
        mock_session = MagicMock()

        with (
            patch(
                "tasks.jobs.attack_paths.findings.get_root_node_label",
                return_value="AWSAccount",
            ),
            patch(
                "tasks.jobs.attack_paths.findings.get_node_uid_field",
                return_value="arn",
            ),
            patch(
                "tasks.jobs.attack_paths.findings.get_provider_resource_label",
                return_value="AWSResource",
            ),
        ):
            findings_module.load_findings(
                mock_session, findings_generator(), provider, config
            )

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

        findings_module.cleanup_findings(mock_session, provider, config)

        assert mock_session.run.call_count == 2
        params = mock_session.run.call_args.args[1]
        assert params["provider_uid"] == str(provider.uid)
        assert params["last_updated"] == config.update_tag

    def test_stream_findings_with_resources_returns_latest_scan_data(
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

        with (
            patch(
                "tasks.jobs.attack_paths.findings.rls_transaction",
                new=lambda *args, **kwargs: nullcontext(),
            ),
            patch(
                "tasks.jobs.attack_paths.findings.READ_REPLICA_ALIAS",
                "default",
            ),
        ):
            # Generator yields batches, collect all findings from all batches
            findings_batches = findings_module.stream_findings_with_resources(
                provider,
                str(latest_scan.id),
            )
            findings_data = []
            for batch in findings_batches:
                findings_data.extend(batch)

        assert len(findings_data) == 1
        finding_result = findings_data[0]
        assert finding_result.id == str(finding.id)
        assert finding_result.resource_uid == resource.uid
        assert finding_result.check_title == "Check title"
        assert finding_result.scan_id == str(latest_scan.id)

    def test_enrich_batch_with_resources_single_resource(
        self,
        tenants_fixture,
        providers_fixture,
    ):
        """One finding + one resource = one output Finding instance"""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()

        resource = Resource.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            uid="resource-uid-1",
            name="Resource 1",
            region="us-east-1",
            service="ec2",
            type="instance",
        )

        scan = Scan.objects.create(
            name="Test Scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant_id=tenant.id,
        )

        finding = Finding.objects.create(
            tenant_id=tenant.id,
            uid="finding-uid",
            scan=scan,
            delta=Finding.DeltaChoices.NEW,
            status=StatusChoices.FAIL,
            status_extended="failed",
            severity=Severity.high,
            impact=Severity.high,
            impact_extended="",
            raw_result={},
            check_id="check-1",
            check_metadata={"checktitle": "Check title"},
            first_seen_at=scan.inserted_at,
        )
        ResourceFindingMapping.objects.create(
            tenant_id=tenant.id,
            resource=resource,
            finding=finding,
        )

        # Simulate the dict returned by .values()
        finding_dict = {
            "id": finding.id,
            "uid": finding.uid,
            "inserted_at": finding.inserted_at,
            "updated_at": finding.updated_at,
            "first_seen_at": finding.first_seen_at,
            "scan_id": scan.id,
            "delta": finding.delta,
            "status": finding.status,
            "status_extended": finding.status_extended,
            "severity": finding.severity,
            "check_id": finding.check_id,
            "check_metadata__checktitle": finding.check_metadata["checktitle"],
            "muted": finding.muted,
            "muted_reason": finding.muted_reason,
        }

        # _enrich_batch_with_resources queries ResourceFindingMapping directly
        # No RLS mock needed - test DB doesn't enforce RLS policies
        with patch(
            "tasks.jobs.attack_paths.findings.READ_REPLICA_ALIAS",
            "default",
        ):
            result = findings_module._enrich_batch_with_resources(
                [finding_dict], str(tenant.id)
            )

        assert len(result) == 1
        assert result[0].resource_uid == resource.uid
        assert result[0].id == str(finding.id)
        assert result[0].status == "FAIL"

    def test_enrich_batch_with_resources_multiple_resources(
        self,
        tenants_fixture,
        providers_fixture,
    ):
        """One finding + three resources = three output Finding instances"""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()

        resources = []
        for i in range(3):
            resource = Resource.objects.create(
                tenant_id=tenant.id,
                provider=provider,
                uid=f"resource-uid-{i}",
                name=f"Resource {i}",
                region="us-east-1",
                service="ec2",
                type="instance",
            )
            resources.append(resource)

        scan = Scan.objects.create(
            name="Test Scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant_id=tenant.id,
        )

        finding = Finding.objects.create(
            tenant_id=tenant.id,
            uid="finding-uid",
            scan=scan,
            delta=Finding.DeltaChoices.NEW,
            status=StatusChoices.FAIL,
            status_extended="failed",
            severity=Severity.high,
            impact=Severity.high,
            impact_extended="",
            raw_result={},
            check_id="check-1",
            check_metadata={"checktitle": "Check title"},
            first_seen_at=scan.inserted_at,
        )

        # Map finding to all 3 resources
        for resource in resources:
            ResourceFindingMapping.objects.create(
                tenant_id=tenant.id,
                resource=resource,
                finding=finding,
            )

        finding_dict = {
            "id": finding.id,
            "uid": finding.uid,
            "inserted_at": finding.inserted_at,
            "updated_at": finding.updated_at,
            "first_seen_at": finding.first_seen_at,
            "scan_id": scan.id,
            "delta": finding.delta,
            "status": finding.status,
            "status_extended": finding.status_extended,
            "severity": finding.severity,
            "check_id": finding.check_id,
            "check_metadata__checktitle": finding.check_metadata["checktitle"],
            "muted": finding.muted,
            "muted_reason": finding.muted_reason,
        }

        # _enrich_batch_with_resources queries ResourceFindingMapping directly
        # No RLS mock needed - test DB doesn't enforce RLS policies
        with patch(
            "tasks.jobs.attack_paths.findings.READ_REPLICA_ALIAS",
            "default",
        ):
            result = findings_module._enrich_batch_with_resources(
                [finding_dict], str(tenant.id)
            )

        assert len(result) == 3
        result_resource_uids = {r.resource_uid for r in result}
        assert result_resource_uids == {r.uid for r in resources}

        # All should have same finding data
        for r in result:
            assert r.id == str(finding.id)
            assert r.status == "FAIL"

    def test_enrich_batch_with_resources_no_resources_skips(
        self,
        tenants_fixture,
        providers_fixture,
    ):
        """Finding without resources should be skipped"""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()

        scan = Scan.objects.create(
            name="Test Scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant_id=tenant.id,
        )

        finding = Finding.objects.create(
            tenant_id=tenant.id,
            uid="orphan-finding",
            scan=scan,
            delta=Finding.DeltaChoices.NEW,
            status=StatusChoices.FAIL,
            status_extended="failed",
            severity=Severity.high,
            impact=Severity.high,
            impact_extended="",
            raw_result={},
            check_id="check-1",
            check_metadata={"checktitle": "Check title"},
            first_seen_at=scan.inserted_at,
        )
        # Note: No ResourceFindingMapping created

        finding_dict = {
            "id": finding.id,
            "uid": finding.uid,
            "inserted_at": finding.inserted_at,
            "updated_at": finding.updated_at,
            "first_seen_at": finding.first_seen_at,
            "scan_id": scan.id,
            "delta": finding.delta,
            "status": finding.status,
            "status_extended": finding.status_extended,
            "severity": finding.severity,
            "check_id": finding.check_id,
            "check_metadata__checktitle": finding.check_metadata["checktitle"],
            "muted": finding.muted,
            "muted_reason": finding.muted_reason,
        }

        # Mock logger to verify no warning is emitted
        with (
            patch(
                "tasks.jobs.attack_paths.findings.READ_REPLICA_ALIAS",
                "default",
            ),
            patch("tasks.jobs.attack_paths.findings.logger") as mock_logger,
        ):
            result = findings_module._enrich_batch_with_resources(
                [finding_dict], str(tenant.id)
            )

        assert len(result) == 0
        mock_logger.warning.assert_not_called()

    def test_generator_is_lazy(self, providers_fixture):
        """Generator should not execute queries until iterated"""
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()
        scan_id = "some-scan-id"

        with (
            patch("tasks.jobs.attack_paths.findings.rls_transaction") as mock_rls,
            patch("tasks.jobs.attack_paths.findings.Finding") as mock_finding,
        ):
            # Create generator but don't iterate
            findings_module.stream_findings_with_resources(provider, scan_id)

            # Nothing should be called yet
            mock_rls.assert_not_called()
            mock_finding.objects.filter.assert_not_called()

    def test_load_findings_empty_generator(self, providers_fixture):
        """Empty generator should not call neo4j"""
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()

        mock_session = MagicMock()
        config = SimpleNamespace(update_tag=12345)

        def empty_gen():
            return
            yield  # Make it a generator

        with (
            patch(
                "tasks.jobs.attack_paths.findings.get_root_node_label",
                return_value="AWSAccount",
            ),
            patch(
                "tasks.jobs.attack_paths.findings.get_node_uid_field",
                return_value="arn",
            ),
            patch(
                "tasks.jobs.attack_paths.findings.get_provider_resource_label",
                return_value="AWSResource",
            ),
        ):
            findings_module.load_findings(mock_session, empty_gen(), provider, config)

        mock_session.run.assert_not_called()


class TestProviderConfigAccessors:
    def test_get_deprecated_provider_resource_label_known_provider(self):
        assert get_deprecated_provider_resource_label("aws") == "AWSResource"

    def test_get_deprecated_provider_resource_label_unknown_provider(self):
        assert (
            get_deprecated_provider_resource_label("unknown")
            == "UnknownProviderResource"
        )


class TestAddResourceLabel:
    def test_add_resource_label_applies_both_labels(self):
        mock_session = MagicMock()

        first_result = MagicMock()
        first_result.single.return_value = {"labeled_count": 5}
        second_result = MagicMock()
        second_result.single.return_value = {"labeled_count": 0}
        mock_session.run.side_effect = [first_result, second_result]

        total = findings_module.add_resource_label(mock_session, "aws", "123456789012")

        assert total == 5
        assert mock_session.run.call_count == 2
        query = mock_session.run.call_args_list[0].args[0]
        assert "_AWSResource" in query
        assert "AWSResource" in query


class TestSyncNodes:
    def test_sync_nodes_adds_both_labels(self):
        mock_source_session = MagicMock()
        mock_target_session = MagicMock()

        row = {
            "internal_id": 1,
            "element_id": "elem-1",
            "labels": ["SomeLabel"],
            "props": {"key": "value"},
        }
        mock_source_session.run.side_effect = [[row], []]

        source_ctx = MagicMock()
        source_ctx.__enter__ = MagicMock(return_value=mock_source_session)
        source_ctx.__exit__ = MagicMock(return_value=False)

        target_ctx = MagicMock()
        target_ctx.__enter__ = MagicMock(return_value=mock_target_session)
        target_ctx.__exit__ = MagicMock(return_value=False)

        with patch(
            "tasks.jobs.attack_paths.sync.graph_database.get_session",
            side_effect=[source_ctx, target_ctx],
        ):
            total = sync_module.sync_nodes("source-db", "target-db", "prov-1")

        assert total == 1
        query = mock_target_session.run.call_args.args[0]
        assert "_ProviderResource" in query
        assert "ProviderResource" in query


class TestInternetAnalysis:
    def _make_provider_and_config(self):
        provider = MagicMock()
        provider.provider = "aws"
        provider.uid = "123456789012"
        config = SimpleNamespace(update_tag=1234567890)
        return provider, config

    def test_analysis_creates_node_and_relationships(self):
        """Verify both Cypher statements are executed and relationship count returned."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"relationships_merged": 3}
        mock_session.run.side_effect = [None, mock_result]
        provider, config = self._make_provider_and_config()

        with patch(
            "tasks.jobs.attack_paths.internet.get_root_node_label",
            return_value="AWSAccount",
        ):
            result = internet_module.analysis(mock_session, provider, config)

        assert mock_session.run.call_count == 2
        assert result == 3

    def test_analysis_zero_exposed_resources(self):
        """When no resources are exposed, zero relationships are created."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"relationships_merged": 0}
        mock_session.run.side_effect = [None, mock_result]
        provider, config = self._make_provider_and_config()

        with patch(
            "tasks.jobs.attack_paths.internet.get_root_node_label",
            return_value="AWSAccount",
        ):
            result = internet_module.analysis(mock_session, provider, config)

        assert result == 0


@pytest.mark.django_db
class TestAttackPathsDbUtilsGraphDataReady:
    """Tests for db_utils functions related to graph_data_ready lifecycle."""

    def test_create_attack_paths_scan_first_scan_defaults_to_false(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import create_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()
        scan = scans_fixture[0]
        scan.provider = provider
        scan.save()

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            attack_paths_scan = create_attack_paths_scan(
                str(tenant.id), str(scan.id), provider.id
            )

        assert attack_paths_scan is not None
        assert attack_paths_scan.graph_data_ready is False

    def test_create_attack_paths_scan_inherits_true_from_previous(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import create_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()
        scan = scans_fixture[0]
        scan.provider = provider
        scan.save()

        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.COMPLETED,
            graph_data_ready=True,
        )

        new_scan = Scan.objects.create(
            name="New Scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            tenant_id=tenant.id,
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            attack_paths_scan = create_attack_paths_scan(
                str(tenant.id), str(new_scan.id), provider.id
            )

        assert attack_paths_scan is not None
        assert attack_paths_scan.graph_data_ready is True

    def test_create_attack_paths_scan_inherits_false_when_no_previous_ready(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import create_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()
        scan = scans_fixture[0]
        scan.provider = provider
        scan.save()

        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.FAILED,
            graph_data_ready=False,
        )

        new_scan = Scan.objects.create(
            name="New Scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            tenant_id=tenant.id,
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            attack_paths_scan = create_attack_paths_scan(
                str(tenant.id), str(new_scan.id), provider.id
            )

        assert attack_paths_scan is not None
        assert attack_paths_scan.graph_data_ready is False

    def test_set_graph_data_ready_updates_field(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import set_graph_data_ready

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
            state=StateChoices.EXECUTING,
            graph_data_ready=True,
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            set_graph_data_ready(attack_paths_scan, False)

        attack_paths_scan.refresh_from_db()
        assert attack_paths_scan.graph_data_ready is False

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            set_graph_data_ready(attack_paths_scan, True)

        attack_paths_scan.refresh_from_db()
        assert attack_paths_scan.graph_data_ready is True

    def test_finish_attack_paths_scan_does_not_modify_graph_data_ready(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import finish_attack_paths_scan

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
            state=StateChoices.EXECUTING,
            graph_data_ready=True,
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            finish_attack_paths_scan(attack_paths_scan, StateChoices.COMPLETED, {})

        attack_paths_scan.refresh_from_db()
        assert attack_paths_scan.state == StateChoices.COMPLETED
        assert attack_paths_scan.graph_data_ready is True

    def test_finish_attack_paths_scan_preserves_graph_data_ready_on_failure(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import finish_attack_paths_scan

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
            state=StateChoices.EXECUTING,
            graph_data_ready=True,
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            finish_attack_paths_scan(
                attack_paths_scan,
                StateChoices.FAILED,
                {"global_error": "boom"},
            )

        attack_paths_scan.refresh_from_db()
        assert attack_paths_scan.state == StateChoices.FAILED
        assert attack_paths_scan.graph_data_ready is True

    def test_set_provider_graph_data_ready_updates_all_scans_for_provider(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import set_provider_graph_data_ready

        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        provider.provider = Provider.ProviderChoices.AWS
        provider.save()

        scan_a = scans_fixture[0]
        scan_a.provider = provider
        scan_a.save()

        scan_b = Scan.objects.create(
            name="Second Scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            tenant_id=tenant.id,
        )

        old_ap_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan_a,
            state=StateChoices.COMPLETED,
            graph_data_ready=True,
        )
        new_ap_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan_b,
            state=StateChoices.EXECUTING,
            graph_data_ready=True,
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            set_provider_graph_data_ready(new_ap_scan, False)

        old_ap_scan.refresh_from_db()
        new_ap_scan.refresh_from_db()
        assert old_ap_scan.graph_data_ready is False
        assert new_ap_scan.graph_data_ready is False

    def test_set_provider_graph_data_ready_does_not_affect_other_providers(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import set_provider_graph_data_ready

        tenant = tenants_fixture[0]
        provider_a = providers_fixture[0]
        provider_a.provider = Provider.ProviderChoices.AWS
        provider_a.save()

        provider_b = providers_fixture[1]
        provider_b.provider = Provider.ProviderChoices.AWS
        provider_b.save()

        scan_a = scans_fixture[0]
        scan_a.provider = provider_a
        scan_a.save()

        scan_b = Scan.objects.create(
            name="Scan for provider B",
            provider=provider_b,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            tenant_id=tenant.id,
        )

        ap_scan_a = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider_a,
            scan=scan_a,
            state=StateChoices.EXECUTING,
            graph_data_ready=True,
        )
        ap_scan_b = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider_b,
            scan=scan_b,
            state=StateChoices.COMPLETED,
            graph_data_ready=True,
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            set_provider_graph_data_ready(ap_scan_a, False)

        ap_scan_a.refresh_from_db()
        ap_scan_b.refresh_from_db()
        assert ap_scan_a.graph_data_ready is False
        assert ap_scan_b.graph_data_ready is True
