import logging
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch
from uuid import uuid4

import pytest
from api.attack_paths.database import GraphDatabaseQueryException
from api.db_utils import rls_transaction
from api.exceptions import ProviderDeletedException
from api.models import (
    AttackPathsScan,
    Finding,
    Provider,
    Resource,
    ResourceFindingMapping,
    Scan,
    StateChoices,
    StatusChoices,
    Task,
)
from django.db import DEFAULT_DB_ALIAS, DatabaseError
from django_celery_results.models import TaskResult
from prowler.lib.check.models import Severity
from tasks.jobs.attack_paths import findings as findings_module
from tasks.jobs.attack_paths import indexes as indexes_module
from tasks.jobs.attack_paths import internet as internet_module
from tasks.jobs.attack_paths import sync as sync_module
from tasks.jobs.attack_paths.scan import run as attack_paths_run

SYNC_RESULT_EMPTY = {
    "nodes": 0,
    "child_nodes": 0,
    "relationships": 0,
    "structural_relationships": 0,
    "item_relationships": 0,
}


@pytest.mark.django_db
class TestAttackPathsRun:
    @pytest.fixture(autouse=True)
    def mock_graph_database_preflight(self):
        with patch(
            "tasks.jobs.attack_paths.scan.graph_database.verify_scan_databases_available"
        ) as mock_preflight:
            yield mock_preflight

    # Patching with decorators as we got a `SyntaxError: too many statically nested blocks` error if we use context managers
    @patch("tasks.jobs.attack_paths.scan.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.scan.utils.call_within_event_loop",
        side_effect=lambda fn, *a, **kw: fn(*a, **kw),
    )
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_scan_migrated")
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_provider_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.finish_attack_paths_scan")
    @patch("tasks.jobs.attack_paths.scan.db_utils.update_attack_paths_scan_progress")
    @patch("tasks.jobs.attack_paths.scan.db_utils.starting_attack_paths_scan")
    @patch(
        "tasks.jobs.attack_paths.scan.sync.sync_graph",
        return_value=SYNC_RESULT_EMPTY,
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.drop_subgraph", return_value=0)
    @patch("tasks.jobs.attack_paths.scan.indexes.create_sync_indexes")
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.analysis", return_value=(0, 0))
    @patch("tasks.jobs.attack_paths.scan.indexes.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_ontology.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.indexes.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.clear_cache")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri",
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
        mock_get_ingest_uri,
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
        mock_set_scan_migrated,
        mock_event_loop,
        mock_drop_db,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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
        config = mock_starting.call_args[0][1]
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
            tenant_id=str(provider.tenant_id),
            provider_id=str(provider.id),
            provider_type="aws",
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
            attack_paths_scan, False, "neo4j"
        )
        mock_set_graph_data_ready.assert_called_once_with(attack_paths_scan, True)
        # is_migrated is flipped to True only after the sync succeeds, so reads
        # don't switch to the new catalog/sink before the graph is live.
        mock_set_scan_migrated.assert_called_once_with(attack_paths_scan, True, "neo4j")

    def test_run_preflight_failure_does_not_start_scan(
        self,
        mock_graph_database_preflight,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.SCHEDULED,
        )
        mock_graph_database_preflight.side_effect = RuntimeError("graph unavailable")

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
                "tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri",
                return_value="bolt://neo4j",
            ),
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ),
            patch(
                "tasks.jobs.attack_paths.scan.get_cartography_ingestion_function",
                return_value=MagicMock(return_value={}),
            ),
            patch(
                "tasks.jobs.attack_paths.scan.db_utils.starting_attack_paths_scan"
            ) as mock_starting,
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.create_database"
            ) as mock_create_db,
        ):
            with pytest.raises(RuntimeError, match="graph unavailable"):
                attack_paths_run(str(tenant.id), str(scan.id), "task-123")

        mock_graph_database_preflight.assert_called_once_with()
        mock_starting.assert_not_called()
        mock_create_db.assert_not_called()

    @pytest.mark.parametrize(
        ("ingestion_error", "temporary_database_missing"),
        [
            (RuntimeError("ingestion boom"), False),
            (
                GraphDatabaseQueryException(
                    message="Graph not found: db-scan-id",
                    code="Neo.ClientError.Database.DatabaseNotFound",
                ),
                True,
            ),
            (
                GraphDatabaseQueryException(
                    message="Graph not found: db-tenant-id",
                    code="Neo.ClientError.Database.DatabaseNotFound",
                ),
                False,
            ),
        ],
        ids=[
            "regular-error",
            "temporary-database-missing",
            "sink-database-missing",
        ],
    )
    @patch("tasks.jobs.attack_paths.scan.logger")
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
    @patch("tasks.jobs.attack_paths.scan.findings.analysis", return_value=(0, 0))
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.indexes.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.indexes.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
        return_value="db-scan-id",
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri")
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
        mock_get_ingest_uri,
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
        mock_logger,
        ingestion_error,
        temporary_database_missing,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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
        ingestion_fn = MagicMock(side_effect=ingestion_error)
        if temporary_database_missing:
            mock_finish.side_effect = DatabaseError(
                "Save with update_fields did not affect any rows"
            )

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
            with pytest.raises(type(ingestion_error)):
                attack_paths_run(str(tenant.id), str(scan.id), "task-456")

        failure_args = mock_finish.call_args[0]
        assert failure_args[0] is attack_paths_scan
        assert failure_args[1] == StateChoices.FAILED
        assert failure_args[2] == {"global_error": "Cartography failed: ingestion boom"}
        mock_drop_db.assert_called_once_with("db-scan-id")
        if temporary_database_missing:
            mock_logger.warning.assert_any_call("Cartography failed: ingestion boom")
            mock_logger.exception.assert_not_called()
            mock_logger.log.assert_called_once_with(
                logging.WARNING,
                f"Could not mark Attack Paths scan {attack_paths_scan.id} as `FAILED` "
                "(row may have been deleted): Save with update_fields did not affect "
                "any rows",
                exc_info=False,
            )
        else:
            mock_logger.exception.assert_called_once_with(
                "Cartography failed: ingestion boom"
            )

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
    @patch("tasks.jobs.attack_paths.scan.findings.analysis", return_value=(0, 0))
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.indexes.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.indexes.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
        return_value="db-scan-id",
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri")
    @patch(
        "tasks.jobs.attack_paths.scan.initialize_prowler_provider",
        return_value=MagicMock(_enabled_regions=["us-east-1"]),
    )
    @patch(
        "tasks.jobs.attack_paths.scan.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    def test_failure_before_gate_does_not_flip_graph_data_ready_true(
        self,
        mock_init_provider,
        mock_get_ingest_uri,
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
        aws_provider,
        scans_fixture,
    ):
        """Failure during ingestion (before set_provider_graph_data_ready(False))
        must NOT flip graph_data_ready to True for providers that never had data."""
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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

        # Gate was never applied, so recovery must not flip anything to True
        mock_set_provider_graph_data_ready.assert_not_called()
        mock_set_graph_data_ready.assert_not_called()

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
    @patch("tasks.jobs.attack_paths.scan.findings.analysis", return_value=(0, 0))
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.indexes.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.indexes.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
        return_value="db-scan-id",
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri")
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
        mock_get_ingest_uri,
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
        aws_provider,
        scans_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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

    @patch(
        "tasks.jobs.attack_paths.scan.utils.stringify_exception",
        return_value="Attack Paths scan failed: drop failed",
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
    @patch(
        "tasks.jobs.attack_paths.scan.sync.sync_graph",
        return_value=SYNC_RESULT_EMPTY,
    )
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.drop_subgraph",
        side_effect=RuntimeError("drop failed"),
    )
    @patch("tasks.jobs.attack_paths.scan.indexes.create_sync_indexes")
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.analysis", return_value=(0, 0))
    @patch("tasks.jobs.attack_paths.scan.indexes.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_ontology.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.indexes.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.clear_cache")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri",
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
    def test_failure_after_gate_before_drop_restores_graph_data_ready(
        self,
        mock_init_provider,
        mock_get_ingest_uri,
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
        mock_set_provider_graph_data_ready,
        mock_set_graph_data_ready,
        mock_finish,
        mock_drop_db,
        mock_event_loop,
        mock_stringify,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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

        with (
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
                side_effect=["db-scan-id", "tenant-db"],
            ),
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
                return_value=MagicMock(return_value={}),
            ),
        ):
            with pytest.raises(RuntimeError, match="drop failed"):
                attack_paths_run(str(tenant.id), str(scan.id), "task-456")

        assert mock_set_provider_graph_data_ready.call_args_list == [
            call(attack_paths_scan, False, "neo4j"),
            call(attack_paths_scan, True, "neo4j"),
        ]

    @patch(
        "tasks.jobs.attack_paths.scan.utils.stringify_exception",
        return_value="Attack Paths scan failed: sync failed",
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
    @patch(
        "tasks.jobs.attack_paths.scan.sync.sync_graph",
        side_effect=RuntimeError("sync failed"),
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.drop_subgraph")
    @patch("tasks.jobs.attack_paths.scan.indexes.create_sync_indexes")
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.analysis", return_value=(0, 0))
    @patch("tasks.jobs.attack_paths.scan.indexes.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_ontology.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.indexes.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.clear_cache")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri",
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
    def test_failure_after_drop_before_sync_leaves_graph_data_ready_false(
        self,
        mock_init_provider,
        mock_get_ingest_uri,
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
        mock_set_provider_graph_data_ready,
        mock_set_graph_data_ready,
        mock_finish,
        mock_drop_db,
        mock_event_loop,
        mock_stringify,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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

        with (
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
                side_effect=["db-scan-id", "tenant-db"],
            ),
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
                return_value=MagicMock(return_value={}),
            ),
        ):
            with pytest.raises(RuntimeError, match="sync failed"):
                attack_paths_run(str(tenant.id), str(scan.id), "task-456")

        # Only called with False (gate), never with True (no recovery for partial data)
        mock_set_provider_graph_data_ready.assert_called_once_with(
            attack_paths_scan, False, "neo4j"
        )

    @patch(
        "tasks.jobs.attack_paths.scan.utils.stringify_exception",
        return_value="Attack Paths scan failed: flag failed",
    )
    @patch(
        "tasks.jobs.attack_paths.scan.utils.call_within_event_loop",
        side_effect=lambda fn, *a, **kw: fn(*a, **kw),
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.scan.db_utils.finish_attack_paths_scan")
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_scan_migrated")
    @patch(
        "tasks.jobs.attack_paths.scan.db_utils.set_graph_data_ready",
        side_effect=[RuntimeError("flag failed"), None],
    )
    @patch("tasks.jobs.attack_paths.scan.db_utils.set_provider_graph_data_ready")
    @patch("tasks.jobs.attack_paths.scan.db_utils.update_attack_paths_scan_progress")
    @patch("tasks.jobs.attack_paths.scan.db_utils.starting_attack_paths_scan")
    @patch(
        "tasks.jobs.attack_paths.scan.sync.sync_graph",
        return_value=SYNC_RESULT_EMPTY,
    )
    @patch("tasks.jobs.attack_paths.scan.graph_database.drop_subgraph")
    @patch("tasks.jobs.attack_paths.scan.indexes.create_sync_indexes")
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.analysis", return_value=(0, 0))
    @patch("tasks.jobs.attack_paths.scan.indexes.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_ontology.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.indexes.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.clear_cache")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri",
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
    def test_failure_after_sync_restores_graph_data_ready(
        self,
        mock_init_provider,
        mock_get_ingest_uri,
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
        mock_set_provider_graph_data_ready,
        mock_set_graph_data_ready,
        mock_set_scan_migrated,
        mock_finish,
        mock_drop_db,
        mock_event_loop,
        mock_stringify,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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

        with (
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
                side_effect=["db-scan-id", "tenant-db"],
            ),
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
                return_value=MagicMock(return_value={}),
            ),
        ):
            with pytest.raises(RuntimeError, match="flag failed"):
                attack_paths_run(str(tenant.id), str(scan.id), "task-456")

        # sync completed: first call (normal path) raised, recovery retried and succeeded
        assert mock_set_graph_data_ready.call_args_list == [
            call(attack_paths_scan, True),
            call(attack_paths_scan, True),
        ]
        # set_provider_graph_data_ready only called once with False (the gate)
        mock_set_provider_graph_data_ready.assert_called_once_with(
            attack_paths_scan, False, "neo4j"
        )
        # is_migrated is flipped once after the sync and is not touched again by
        # the failure-recovery branch
        mock_set_scan_migrated.assert_called_once_with(attack_paths_scan, True, "neo4j")

    @patch(
        "tasks.jobs.attack_paths.scan.utils.stringify_exception",
        return_value="Attack Paths scan failed: drop failed",
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
    @patch(
        "tasks.jobs.attack_paths.scan.sync.sync_graph",
        return_value=SYNC_RESULT_EMPTY,
    )
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.drop_subgraph",
        side_effect=RuntimeError("drop failed"),
    )
    @patch("tasks.jobs.attack_paths.scan.indexes.create_sync_indexes")
    @patch("tasks.jobs.attack_paths.scan.internet.analysis")
    @patch("tasks.jobs.attack_paths.scan.findings.analysis", return_value=(0, 0))
    @patch("tasks.jobs.attack_paths.scan.indexes.create_findings_indexes")
    @patch("tasks.jobs.attack_paths.scan.cartography_ontology.run")
    @patch("tasks.jobs.attack_paths.scan.cartography_analysis.run")
    @patch("tasks.jobs.attack_paths.indexes.cartography_create_indexes.run")
    @patch("tasks.jobs.attack_paths.scan.graph_database.clear_cache")
    @patch("tasks.jobs.attack_paths.scan.graph_database.create_database")
    @patch(
        "tasks.jobs.attack_paths.scan.graph_database.get_ingest_uri",
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
    def test_recovery_failure_does_not_suppress_original_exception(
        self,
        mock_init_provider,
        mock_get_ingest_uri,
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
        mock_set_provider_graph_data_ready,
        mock_set_graph_data_ready,
        mock_finish,
        mock_drop_db,
        mock_event_loop,
        mock_stringify,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.SCHEDULED,
        )

        # Recovery itself fails on the second call (True)
        mock_set_provider_graph_data_ready.side_effect = [
            None,
            RuntimeError("recovery boom"),
        ]

        mock_session = MagicMock()
        session_ctx = MagicMock()
        session_ctx.__enter__.return_value = mock_session
        session_ctx.__exit__.return_value = False

        with (
            patch(
                "tasks.jobs.attack_paths.scan.graph_database.get_database_name",
                side_effect=["db-scan-id", "tenant-db"],
            ),
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
                return_value=MagicMock(return_value={}),
            ),
        ):
            # Original exception propagates despite recovery failure
            with pytest.raises(RuntimeError, match="drop failed"):
                attack_paths_run(str(tenant.id), str(scan.id), "task-456")

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
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import fail_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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
            patch("tasks.jobs.attack_paths.db_utils.recover_graph_data_ready"),
        ):
            fail_attack_paths_scan(str(tenant.id), str(scan.id), "setup exploded")

        mock_retrieve.assert_called_once_with(str(tenant.id), str(scan.id))
        expected_tmp_db = f"db-tmp-scan-{str(attack_paths_scan.id).lower()}"
        mock_drop_db.assert_called_once_with(expected_tmp_db)

        attack_paths_scan.refresh_from_db()
        assert attack_paths_scan.state == StateChoices.FAILED
        assert attack_paths_scan.ingestion_exceptions == {
            "global_error": "setup exploded"
        }

    def test_drops_temp_database_even_when_drop_fails(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import fail_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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
            patch("tasks.jobs.attack_paths.db_utils.recover_graph_data_ready"),
        ):
            fail_attack_paths_scan(str(tenant.id), str(scan.id), "setup exploded")

        attack_paths_scan.refresh_from_db()
        assert attack_paths_scan.state == StateChoices.FAILED

    def test_skips_already_failed_scan(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import fail_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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
        ):
            fail_attack_paths_scan(str(tenant.id), str(scan.id), "setup exploded")

        mock_drop_db.assert_called_once()

        attack_paths_scan.refresh_from_db()
        assert attack_paths_scan.state == StateChoices.FAILED

    def test_skips_when_no_scan_found(self, tenants_fixture):
        from tasks.jobs.attack_paths.db_utils import fail_attack_paths_scan

        tenant = tenants_fixture[0]

        with patch(
            "tasks.jobs.attack_paths.db_utils.retrieve_attack_paths_scan",
            return_value=None,
        ):
            fail_attack_paths_scan(str(tenant.id), "nonexistent", "setup exploded")

    def test_fail_recovers_graph_data_ready_when_data_exists(
        self, tenants_fixture, aws_provider, scans_fixture, sink_backend_stub
    ):
        from tasks.jobs.attack_paths.db_utils import fail_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.EXECUTING,
        )

        # `recover_graph_data_ready` routes `has_provider_data` through
        # `sink_module.get_backend_for_scan(scan)`. With `is_migrated=False`
        # and the default `ATTACK_PATHS_SINK_DATABASE=neo4j`, the factory
        # returns the active backend, which `sink_backend_stub` replaces.
        sink_backend_stub.has_provider_data.return_value = True

        with (
            patch(
                "tasks.jobs.attack_paths.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ),
            patch("tasks.jobs.attack_paths.db_utils.graph_database.drop_database"),
            patch(
                "tasks.jobs.attack_paths.db_utils.set_provider_graph_data_ready"
            ) as mock_set_ready,
        ):
            fail_attack_paths_scan(str(tenant.id), str(scan.id), "worker died")

        mock_set_ready.assert_called_once_with(attack_paths_scan, True)

    def test_fail_leaves_graph_data_ready_false_when_no_data(
        self, tenants_fixture, aws_provider, scans_fixture, sink_backend_stub
    ):
        from tasks.jobs.attack_paths.db_utils import fail_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.EXECUTING,
        )

        sink_backend_stub.has_provider_data.return_value = False

        with (
            patch(
                "tasks.jobs.attack_paths.db_utils.retrieve_attack_paths_scan",
                return_value=attack_paths_scan,
            ),
            patch("tasks.jobs.attack_paths.db_utils.graph_database.drop_database"),
            patch(
                "tasks.jobs.attack_paths.db_utils.set_provider_graph_data_ready"
            ) as mock_set_ready,
        ):
            fail_attack_paths_scan(str(tenant.id), str(scan.id), "worker died")

        mock_set_ready.assert_not_called()

    def test_recover_graph_data_ready_never_raises(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import recover_graph_data_ready

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.EXECUTING,
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.graph_database.has_provider_data",
            side_effect=Exception("Neo4j unreachable"),
        ):
            # Should not raise
            recover_graph_data_ready(attack_paths_scan)


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

    def test_on_failure_logs_provider_deletion_as_warning(self):
        from tasks.tasks import AttackPathsScanRLSTask

        task = AttackPathsScanRLSTask()
        error = ProviderDeletedException("provider deleted")

        with (
            patch("tasks.tasks.logger") as mock_logger,
            patch(
                "tasks.tasks.attack_paths_db_utils.fail_attack_paths_scan"
            ) as mock_fail,
        ):
            task.on_failure(
                exc=error,
                task_id="task-abc",
                args=(),
                kwargs={"tenant_id": "t-1", "scan_id": "s-1"},
                _einfo=None,
            )

        mock_logger.warning.assert_called_once_with(
            "Attack paths scan task task-abc stopped because its provider or tenant "
            "was deleted: provider deleted"
        )
        mock_logger.error.assert_not_called()
        mock_fail.assert_called_once_with("t-1", "s-1", "provider deleted")

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
            indexes_module.create_findings_indexes(mock_session)

        from tasks.jobs.attack_paths.indexes import FINDINGS_INDEX_STATEMENTS

        assert mock_run_write.call_count == len(FINDINGS_INDEX_STATEMENTS)
        mock_run_write.assert_has_calls(
            [call(mock_session, stmt) for stmt in FINDINGS_INDEX_STATEMENTS]
        )

    def test_create_findings_indexes_runs_even_when_sink_is_neptune(self, settings):
        # The index helpers run against the temp ingest DB, which is always
        # Neo4j regardless of the configured sink. A Neptune sink must not
        # suppress index creation on that DB (regression for the dropped
        # in-helper sink gate).
        settings.ATTACK_PATHS_SINK_DATABASE = "neptune"
        mock_session = MagicMock()
        with patch("tasks.jobs.attack_paths.indexes.run_write_query") as mock_run_write:
            indexes_module.create_findings_indexes(mock_session)

        from tasks.jobs.attack_paths.indexes import FINDINGS_INDEX_STATEMENTS

        assert mock_run_write.call_count == len(FINDINGS_INDEX_STATEMENTS)

    def test_load_findings_batches_requests(self, aws_provider):
        provider = aws_provider

        # Create a generator that yields two batches of dicts (pre-converted)
        def findings_generator():
            yield [{"id": "1", "resource_uid": "r-1"}]
            yield [{"id": "2", "resource_uid": "r-2"}]

        config = SimpleNamespace(update_tag=12345)
        mock_session = MagicMock()

        first_result = MagicMock()
        first_result.single.return_value = {"merged_count": 1, "dropped_count": 0}
        second_result = MagicMock()
        second_result.single.return_value = {"merged_count": 0, "dropped_count": 1}
        mock_session.run.side_effect = [first_result, second_result]

        with (
            patch(
                "tasks.jobs.attack_paths.findings.get_node_uid_field",
                return_value="arn",
            ),
            patch(
                "tasks.jobs.attack_paths.findings.get_provider_resource_label",
                return_value="_AWSResource",
            ),
            patch("tasks.jobs.attack_paths.findings.logger") as mock_logger,
        ):
            findings_module.load_findings(
                mock_session, findings_generator(), provider, config
            )

        assert mock_session.run.call_count == 2
        for call_args in mock_session.run.call_args_list:
            params = call_args.args[1]
            assert params["last_updated"] == config.update_tag
            assert "findings_data" in params

        summary_log = next(
            call_args.args[0]
            for call_args in mock_logger.info.call_args_list
            if call_args.args and "Finished loading" in call_args.args[0]
        )
        assert "edges_merged=1" in summary_log
        assert "edges_dropped=1" in summary_log

    def test_stream_findings_with_resources_returns_latest_scan_data(
        self,
        tenants_fixture,
        aws_provider,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider

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
        assert finding_result["id"] == str(finding.id)
        assert finding_result["resource_uid"] == resource.uid
        assert finding_result["check_title"] == "Check title"
        assert finding_result["scan_id"] == str(latest_scan.id)

    def test_enrich_batch_with_resources_single_resource(
        self,
        tenants_fixture,
        aws_provider,
    ):
        """One finding + one resource = one output dict"""
        tenant = tenants_fixture[0]
        provider = aws_provider

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
                [finding_dict], str(tenant.id), lambda uid: f"short:{uid}"
            )

        assert len(result) == 1
        assert result[0]["resource_uid"] == resource.uid
        assert result[0]["resource_short_uid"] == f"short:{resource.uid}"
        assert result[0]["id"] == str(finding.id)
        assert result[0]["status"] == "FAIL"

    def test_enrich_batch_with_resources_multiple_resources(
        self,
        tenants_fixture,
        aws_provider,
    ):
        """One finding + three resources = three output dicts"""
        tenant = tenants_fixture[0]
        provider = aws_provider

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
                [finding_dict], str(tenant.id), lambda uid: uid
            )

        assert len(result) == 3
        result_resource_uids = {r["resource_uid"] for r in result}
        assert result_resource_uids == {r.uid for r in resources}

        # All should have same finding data
        for r in result:
            assert r["id"] == str(finding.id)
            assert r["status"] == "FAIL"

    def test_enrich_batch_with_resources_no_resources_skips(
        self,
        tenants_fixture,
        aws_provider,
    ):
        """Finding without resources should be skipped"""
        tenant = tenants_fixture[0]
        provider = aws_provider

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
                [finding_dict], str(tenant.id), lambda uid: uid
            )

        assert len(result) == 0
        mock_logger.warning.assert_not_called()

    def test_generator_is_lazy(self, aws_provider):
        """Generator should not execute queries until iterated"""
        provider = aws_provider
        scan_id = "some-scan-id"

        with patch("tasks.jobs.attack_paths.findings.rls_transaction") as mock_rls:
            # Create generator but don't iterate
            findings_module.stream_findings_with_resources(provider, scan_id)

            # Nothing should be called yet
            mock_rls.assert_not_called()

    def test_load_findings_empty_generator(self, aws_provider):
        """Empty generator should not call neo4j"""
        provider = aws_provider

        mock_session = MagicMock()
        config = SimpleNamespace(update_tag=12345)

        def empty_gen():
            return
            yield  # Make it a generator

        with (
            patch(
                "tasks.jobs.attack_paths.findings.get_node_uid_field",
                return_value="arn",
            ),
            patch(
                "tasks.jobs.attack_paths.findings.get_provider_resource_label",
                return_value="_AWSResource",
            ),
        ):
            findings_module.load_findings(mock_session, empty_gen(), provider, config)

        mock_session.run.assert_not_called()

    @pytest.mark.parametrize(
        "uid, expected",
        [
            (
                "arn:aws:ec2:us-east-1:552455647653:instance/i-05075b63eb51baacb",
                "i-05075b63eb51baacb",
            ),
            (
                "arn:aws:ec2:us-east-1:123456789012:volume/vol-0abcd1234ef567890",
                "vol-0abcd1234ef567890",
            ),
            (
                "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123abcd",
                "sg-0123abcd",
            ),
            ("arn:aws:s3:::my-bucket-name", "my-bucket-name"),
            ("arn:aws:iam::123456789012:role/MyRole", "MyRole"),
            (
                "arn:aws:lambda:us-east-1:123456789012:function:my-function",
                "my-function",
            ),
            ("i-05075b63eb51baacb", "i-05075b63eb51baacb"),
        ],
    )
    def test_extract_short_uid_aws_variants(self, uid, expected):
        from tasks.jobs.attack_paths.aws import extract_short_uid

        assert extract_short_uid(uid) == expected

    def test_insert_finding_template_has_short_id_fallback(self):
        from tasks.jobs.attack_paths.queries import (
            INSERT_FINDING_TEMPLATE,
            render_cypher_template,
        )

        rendered = render_cypher_template(
            INSERT_FINDING_TEMPLATE,
            {
                "__NODE_UID_FIELD__": "arn",
                "__RESOURCE_LABEL__": "_AWSResource",
            },
        )

        assert (
            "resource_by_uid:_AWSResource {arn: finding_data.resource_uid}" in rendered
        )
        assert "resource_by_id:_AWSResource {id: finding_data.resource_uid}" in rendered
        assert (
            "resource_by_short:_AWSResource {id: finding_data.resource_short_uid}"
            in rendered
        )
        assert "head(collect(resource_by_short)) AS resource_by_short" in rendered
        assert (
            "COALESCE(resource_by_uid, resource_by_id, resource_by_short)" in rendered
        )
        assert "RETURN merged_count, dropped_count" in rendered


class TestAddResourceLabel:
    def test_add_resource_label_applies_private_label(self):
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
        assert "AWSResource" not in query.replace("_AWSResource", "")


def _make_session_ctx(session, call_order=None, name=None):
    """Create a mock context manager wrapping a mock session."""
    ctx = MagicMock()
    if call_order is not None and name is not None:
        ctx.__enter__ = MagicMock(
            side_effect=lambda: (call_order.append(f"{name}:enter"), session)[1]
        )
        ctx.__exit__ = MagicMock(
            side_effect=lambda *a: (call_order.append(f"{name}:exit"), False)[1]
        )
    else:
        ctx.__enter__ = MagicMock(return_value=session)
        ctx.__exit__ = MagicMock(return_value=False)
    return ctx


class TestBuildChildId:
    def test_large_value_is_hashed_and_preserved_as_child_data(self):
        value = "x" * 22_796
        spec = sync_module.NormalizedList(
            "SomeLabel",
            "values",
            "SomeLabelValuesItem",
            "HAS_VALUES",
        )
        record = {
            "element_id": "elem-1",
            "labels": ["SomeLabel"],
            "props": {"values": [value]},
        }

        _, parent, children, relationships = sync_module._node_to_sync_dict(
            record,
            "prov-1",
            sync_module._build_catalog_index([spec]),
        )

        child = children[0]["row"]
        child_id = child["provider_element_id"]
        prefix = "prov-1::SomeLabelValuesItem::"
        assert parent["provider_element_id"] == "prov-1:elem-1"
        assert child["props"]["value"] == value
        assert len(child_id) == len(prefix) + 64
        assert value not in child_id
        assert relationships[0]["row"]["end_element_id"] == child_id

    @pytest.mark.parametrize(
        ("provider_id", "child_label", "value_key"),
        [
            ("prov-2", "ChildLabel", "value"),
            ("prov-1", "OtherChildLabel", "value"),
            ("prov-1", "ChildLabel", "other-value"),
        ],
    )
    def test_each_identity_component_changes_id(
        self, provider_id, child_label, value_key
    ):
        child_id = sync_module._build_child_id("prov-1", "ChildLabel", "value")

        assert sync_module._build_child_id("prov-1", "ChildLabel", "value") == child_id
        assert (
            sync_module._build_child_id(provider_id, child_label, value_key) != child_id
        )


class TestSyncNodes:
    def test_iter_sink_batches_rejects_zero_batch_size(self):
        with pytest.raises(
            ValueError, match="Sink batch size must be greater than zero"
        ):
            list(sync_module._iter_sink_batches([], batch_size=0))

    def test_sync_nodes_passes_isolation_labels_to_sink(self):
        row = {
            "internal_id": 1,
            "element_id": "elem-1",
            "labels": ["SomeLabel"],
            "props": {"key": "value"},
        }

        mock_source_1 = MagicMock()
        mock_source_1.run.return_value = [row]
        mock_source_2 = MagicMock()
        mock_source_2.run.return_value = []
        sink = MagicMock()

        with patch(
            "tasks.jobs.attack_paths.sync.graph_database.get_session",
            side_effect=[
                _make_session_ctx(mock_source_1),
                _make_session_ctx(mock_source_2),
            ],
        ):
            result = sync_module.sync_nodes(
                "source-db", "target-db", "tenant-1", "prov-1", sink, []
            )

        assert result["parents"] == 1
        sink.write_nodes.assert_called_once()
        target_db, labels, batch = sink.write_nodes.call_args.args
        assert target_db == "target-db"
        assert "_ProviderResource" in labels
        assert "_Tenant_tenant1" in labels
        assert "_Provider_prov1" in labels
        assert batch[0]["provider_element_id"] == "prov-1:elem-1"
        assert batch[0]["props"] == {"key": "value"}

    def test_sync_nodes_writes_after_source_session_closes(self):
        row = {
            "internal_id": 1,
            "element_id": "elem-1",
            "labels": ["SomeLabel"],
            "props": {"key": "value"},
        }

        call_order = []

        src_1 = MagicMock()
        src_1.run.return_value = [row]
        src_2 = MagicMock()
        src_2.run.return_value = []
        sink = MagicMock()
        sink.write_nodes.side_effect = lambda *_a, **_kw: call_order.append(
            "sink:write"
        )

        with patch(
            "tasks.jobs.attack_paths.sync.graph_database.get_session",
            side_effect=[
                _make_session_ctx(src_1, call_order, "source1"),
                _make_session_ctx(src_2, call_order, "source2"),
            ],
        ):
            sync_module.sync_nodes("src-db", "tgt-db", "t-1", "p-1", sink, [])

        assert call_order.index("source1:exit") < call_order.index("sink:write")

    def test_sync_nodes_pagination_with_batch_size_1(self):
        row_a = {
            "internal_id": 1,
            "element_id": "elem-1",
            "labels": ["LabelA"],
            "props": {"a": 1},
        }
        row_b = {
            "internal_id": 2,
            "element_id": "elem-2",
            "labels": ["LabelB"],
            "props": {"b": 2},
        }

        src_1 = MagicMock()
        src_1.run.return_value = [row_a]
        src_2 = MagicMock()
        src_2.run.return_value = [row_b]
        src_3 = MagicMock()
        src_3.run.return_value = []
        sink = MagicMock()

        with (
            patch(
                "tasks.jobs.attack_paths.sync.graph_database.get_session",
                side_effect=[
                    _make_session_ctx(src_1),
                    _make_session_ctx(src_2),
                    _make_session_ctx(src_3),
                ],
            ),
            patch("tasks.jobs.attack_paths.sync.SYNC_BATCH_SIZE", 1),
        ):
            result = sync_module.sync_nodes("src", "tgt", "t-1", "p-1", sink, [])

        assert result["parents"] == 2
        assert sink.write_nodes.call_count == 2
        assert src_1.run.call_args.args[1]["last_id"] == -1
        assert src_2.run.call_args.args[1]["last_id"] == 1

    def test_sync_nodes_chunks_expanded_list_rows_before_sink_write(self):
        row = {
            "internal_id": 1,
            "element_id": "elem-1",
            "labels": ["SomeLabel"],
            "props": {"values": ["a", "b", "c", "d", "e"]},
        }
        normalized_lists = [
            sync_module.NormalizedList(
                "SomeLabel",
                "values",
                "SomeLabelValuesItem",
                "HAS_VALUES",
            )
        ]

        src_1 = MagicMock()
        src_1.run.return_value = [row]
        src_2 = MagicMock()
        src_2.run.return_value = []
        sink = MagicMock()

        with (
            patch(
                "tasks.jobs.attack_paths.sync.graph_database.get_session",
                side_effect=[
                    _make_session_ctx(src_1),
                    _make_session_ctx(src_2),
                ],
            ),
            patch("tasks.jobs.attack_paths.sync.SYNC_BATCH_SIZE", 2),
        ):
            result = sync_module.sync_nodes(
                "src", "tgt", "t-1", "p-1", sink, normalized_lists
            )

        assert result == {"parents": 1, "children": 5, "parent_child_rels": 5}
        assert [
            len(call_args.args[2]) for call_args in sink.write_nodes.call_args_list[1:]
        ] == [2, 2, 1]
        assert [
            len(call_args.args[3])
            for call_args in sink.write_relationships.call_args_list
        ] == [2, 2, 1]

    def test_sync_nodes_empty_source_returns_zero(self):
        src = MagicMock()
        src.run.return_value = []
        sink = MagicMock()

        with patch(
            "tasks.jobs.attack_paths.sync.graph_database.get_session",
            side_effect=[_make_session_ctx(src)],
        ) as mock_get_session:
            result = sync_module.sync_nodes("src", "tgt", "t-1", "p-1", sink, [])

        assert result["parents"] == 0
        assert mock_get_session.call_count == 1
        sink.write_nodes.assert_not_called()


class TestSyncRelationships:
    def test_sync_relationships_writes_after_source_session_closes(self):
        row = {
            "internal_id": 1,
            "rel_type": "HAS",
            "start_element_id": "s-1",
            "end_element_id": "e-1",
            "props": {},
        }

        call_order = []

        src_1 = MagicMock()
        src_1.run.return_value = [row]
        src_2 = MagicMock()
        src_2.run.return_value = []
        sink = MagicMock()
        sink.write_relationships.side_effect = lambda *_a, **_kw: call_order.append(
            "sink:write"
        )

        with patch(
            "tasks.jobs.attack_paths.sync.graph_database.get_session",
            side_effect=[
                _make_session_ctx(src_1, call_order, "source1"),
                _make_session_ctx(src_2, call_order, "source2"),
            ],
        ):
            sync_module.sync_relationships("src", "tgt", "p-1", sink)

        assert call_order.index("source1:exit") < call_order.index("sink:write")

    def test_sync_relationships_pagination_with_batch_size_1(self):
        row_a = {
            "internal_id": 1,
            "rel_type": "HAS",
            "start_element_id": "s-1",
            "end_element_id": "e-1",
            "props": {"a": 1},
        }
        row_b = {
            "internal_id": 2,
            "rel_type": "CONNECTS",
            "start_element_id": "s-2",
            "end_element_id": "e-2",
            "props": {"b": 2},
        }

        src_1 = MagicMock()
        src_1.run.return_value = [row_a]
        src_2 = MagicMock()
        src_2.run.return_value = [row_b]
        src_3 = MagicMock()
        src_3.run.return_value = []
        sink = MagicMock()

        with (
            patch(
                "tasks.jobs.attack_paths.sync.graph_database.get_session",
                side_effect=[
                    _make_session_ctx(src_1),
                    _make_session_ctx(src_2),
                    _make_session_ctx(src_3),
                ],
            ),
            patch("tasks.jobs.attack_paths.sync.SYNC_BATCH_SIZE", 1),
        ):
            total = sync_module.sync_relationships("src", "tgt", "p-1", sink)

        assert total == 2
        assert sink.write_relationships.call_count == 2
        assert src_1.run.call_args.args[1]["last_id"] == -1
        assert src_2.run.call_args.args[1]["last_id"] == 1

    def test_sync_relationships_chunks_grouped_rows_before_sink_write(self):
        rows = [
            {
                "internal_id": idx,
                "rel_type": "HAS",
                "start_element_id": f"s-{idx}",
                "end_element_id": f"e-{idx}",
                "props": {},
            }
            for idx in range(1, 6)
        ]

        src_1 = MagicMock()
        src_1.run.return_value = rows
        src_2 = MagicMock()
        src_2.run.return_value = []
        sink = MagicMock()

        with (
            patch(
                "tasks.jobs.attack_paths.sync.graph_database.get_session",
                side_effect=[
                    _make_session_ctx(src_1),
                    _make_session_ctx(src_2),
                ],
            ),
            patch("tasks.jobs.attack_paths.sync.SYNC_BATCH_SIZE", 2),
        ):
            total = sync_module.sync_relationships("src", "tgt", "p-1", sink)

        assert total == 5
        assert [
            len(call_args.args[3])
            for call_args in sink.write_relationships.call_args_list
        ] == [2, 2, 1]

    def test_sync_relationships_empty_source_returns_zero(self):
        src = MagicMock()
        src.run.return_value = []
        sink = MagicMock()

        with patch(
            "tasks.jobs.attack_paths.sync.graph_database.get_session",
            side_effect=[_make_session_ctx(src)],
        ) as mock_get_session:
            total = sync_module.sync_relationships("src", "tgt", "p-1", sink)

        assert total == 0
        assert mock_get_session.call_count == 1
        sink.write_relationships.assert_not_called()


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

    def test_database_defaults_allow_legacy_insert_without_cutover_columns(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        attack_paths_scan_id = uuid4()
        now = datetime.now(tz=UTC)

        with rls_transaction(str(tenant.id), using=DEFAULT_DB_ALIAS) as cursor:
            cursor.execute(
                """
                INSERT INTO attack_paths_scans (
                    id,
                    inserted_at,
                    updated_at,
                    state,
                    progress,
                    graph_data_ready,
                    started_at,
                    tenant_id,
                    provider_id,
                    scan_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [
                    attack_paths_scan_id,
                    now,
                    now,
                    StateChoices.SCHEDULED,
                    0,
                    False,
                    now,
                    tenant.id,
                    provider.id,
                    scan.id,
                ],
            )

            attack_paths_scan = AttackPathsScan.objects.get(id=attack_paths_scan_id)

        assert attack_paths_scan.is_migrated is False
        assert (
            attack_paths_scan.sink_backend == AttackPathsScan.SinkBackendChoices.NEO4J
        )

    def test_create_attack_paths_scan_first_scan_defaults_to_false(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import create_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            attack_paths_scan = create_attack_paths_scan(
                str(tenant.id), str(scan.id), provider.id
            )

        assert attack_paths_scan is not None
        assert attack_paths_scan.graph_data_ready is False
        assert attack_paths_scan.is_migrated is False
        assert attack_paths_scan.sink_backend == "neo4j"

    def test_create_attack_paths_scan_inherits_true_from_previous(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import create_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.COMPLETED,
            graph_data_ready=True,
            is_migrated=True,
            sink_backend="neptune",
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
        # is_migrated tracks the data being served: inherited from the ready scan
        assert attack_paths_scan.is_migrated is True
        assert attack_paths_scan.sink_backend == "neptune"

    def test_create_attack_paths_scan_prefers_active_sink_ready_scan(
        self, tenants_fixture, aws_provider, scans_fixture, settings
    ):
        from tasks.jobs.attack_paths.db_utils import create_attack_paths_scan

        settings.ATTACK_PATHS_SINK_DATABASE = "neo4j"
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.COMPLETED,
            graph_data_ready=True,
            is_migrated=False,
            sink_backend="neo4j",
        )
        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.COMPLETED,
            graph_data_ready=True,
            is_migrated=True,
            sink_backend="neptune",
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
        assert attack_paths_scan.is_migrated is False
        assert attack_paths_scan.sink_backend == "neo4j"

    def test_create_attack_paths_scan_inherits_is_migrated_false_from_legacy_ready(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import create_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        # Previous scan is ready but pre-cutover (legacy Neo4j graph shape)
        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.COMPLETED,
            graph_data_ready=True,
            is_migrated=False,
            sink_backend="neo4j",
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
        # Reads stay on the legacy catalog/backend until this scan's own sync
        assert attack_paths_scan.is_migrated is False
        assert attack_paths_scan.sink_backend == "neo4j"

    def test_create_attack_paths_scan_inherits_false_when_no_previous_ready(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import create_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.FAILED,
            graph_data_ready=False,
            sink_backend="neptune",
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
        assert attack_paths_scan.is_migrated is False
        assert attack_paths_scan.sink_backend == "neo4j"

    def test_set_graph_data_ready_updates_field(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import set_graph_data_ready

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import finish_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import finish_attack_paths_scan

        tenant = tenants_fixture[0]
        provider = aws_provider
        scan = scans_fixture[0]

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

    def test_set_provider_graph_data_ready_updates_all_scans_for_provider_sink(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import set_provider_graph_data_ready

        tenant = tenants_fixture[0]
        provider = aws_provider

        scan_a = scans_fixture[0]

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
            sink_backend="neptune",
        )
        new_ap_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan_b,
            state=StateChoices.EXECUTING,
            graph_data_ready=True,
            sink_backend="neptune",
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

    def test_set_provider_graph_data_ready_preserves_other_sink_scans(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import set_provider_graph_data_ready

        tenant = tenants_fixture[0]
        provider = aws_provider

        scan = scans_fixture[0]

        legacy_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.COMPLETED,
            graph_data_ready=True,
            sink_backend="neo4j",
        )
        neptune_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.EXECUTING,
            graph_data_ready=True,
            sink_backend="neptune",
        )

        with patch(
            "tasks.jobs.attack_paths.db_utils.rls_transaction",
            new=lambda *args, **kwargs: nullcontext(),
        ):
            set_provider_graph_data_ready(neptune_scan, False)

        legacy_scan.refresh_from_db()
        neptune_scan.refresh_from_db()
        assert legacy_scan.graph_data_ready is True
        assert neptune_scan.graph_data_ready is False

    def test_set_provider_graph_data_ready_does_not_affect_other_providers(
        self, tenants_fixture, aws_provider_pair, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import set_provider_graph_data_ready

        tenant = tenants_fixture[0]
        provider_a, provider_b = aws_provider_pair

        scan_a = scans_fixture[0]

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


class TestAttackPathsWorkerPing:
    @patch("tasks.jobs.attack_paths.cleanup.current_app")
    def test_pings_workers_in_parallel_and_retries_only_missing(self, mock_app):
        from tasks.jobs.attack_paths.cleanup import _ping_workers

        first_ping = MagicMock(return_value={"worker-a@host": {"ok": "pong"}})
        second_ping = MagicMock(return_value={"worker-b@host": {"ok": "pong"}})
        third_ping = MagicMock(return_value={"worker-c@host": {"ok": "pong"}})
        mock_app.control.inspect.side_effect = [
            MagicMock(ping=first_ping),
            MagicMock(ping=second_ping),
            MagicMock(ping=third_ping),
        ]

        responsive, unresponsive = _ping_workers(
            {"worker-c@host", "worker-a@host", "worker-b@host"}
        )

        assert responsive == {
            "worker-a@host",
            "worker-b@host",
            "worker-c@host",
        }
        assert unresponsive == set()
        assert mock_app.control.inspect.call_args_list == [
            call(
                destination=["worker-a@host", "worker-b@host", "worker-c@host"],
                timeout=5,
            ),
            call(destination=["worker-b@host", "worker-c@host"], timeout=10),
            call(destination=["worker-c@host"], timeout=20),
        ]

    @patch("tasks.jobs.attack_paths.cleanup.logger")
    @patch("tasks.jobs.attack_paths.cleanup.current_app")
    def test_retries_intermediate_ping_exceptions(self, mock_app, mock_logger):
        from tasks.jobs.attack_paths.cleanup import _ping_workers

        mock_app.control.inspect.side_effect = [
            MagicMock(ping=MagicMock(side_effect=ConnectionError("first"))),
            MagicMock(ping=MagicMock(side_effect=ConnectionError("second"))),
            MagicMock(ping=MagicMock(return_value={})),
        ]

        responsive, unresponsive = _ping_workers({"worker@host"})

        assert responsive == set()
        assert unresponsive == {"worker@host"}
        assert mock_logger.warning.call_count == 2
        assert all(
            warning.kwargs["exc_info"] is True
            for warning in mock_logger.warning.call_args_list
        )
        mock_logger.exception.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.logger")
    @patch("tasks.jobs.attack_paths.cleanup.current_app")
    def test_final_ping_exception_leaves_pending_workers_unknown(
        self, mock_app, mock_logger
    ):
        from tasks.jobs.attack_paths.cleanup import _ping_workers

        mock_app.control.inspect.side_effect = [
            MagicMock(ping=MagicMock(return_value={"worker-a@host": {"ok": "pong"}})),
            MagicMock(ping=MagicMock(return_value={})),
            MagicMock(ping=MagicMock(side_effect=ConnectionError("final"))),
        ]

        responsive, unresponsive = _ping_workers({"worker-a@host", "worker-b@host"})

        assert responsive == {"worker-a@host"}
        assert unresponsive is None
        mock_logger.exception.assert_called_once()

    @patch("tasks.jobs.attack_paths.cleanup.logger")
    @patch("tasks.jobs.attack_paths.cleanup.current_app")
    def test_worker_can_respond_after_an_intermediate_exception(
        self, mock_app, mock_logger
    ):
        from tasks.jobs.attack_paths.cleanup import _ping_workers

        mock_app.control.inspect.side_effect = [
            MagicMock(ping=MagicMock(side_effect=ConnectionError("first"))),
            MagicMock(ping=MagicMock(side_effect=ConnectionError("second"))),
            MagicMock(ping=MagicMock(return_value={"worker@host": {"ok": "pong"}})),
        ]

        responsive, unresponsive = _ping_workers({"worker@host"})

        assert responsive == {"worker@host"}
        assert unresponsive == set()
        assert mock_logger.warning.call_count == 2
        mock_logger.exception.assert_not_called()


class TestAttackPathsCleanupTask:
    @patch(
        "tasks.tasks.cleanup_stale_attack_paths_scans",
        return_value={"cleaned_up_count": 1, "scan_ids": ["scan-id"]},
    )
    def test_hourly_task_invokes_attack_paths_cleanup(self, mock_cleanup):
        from tasks.tasks import cleanup_stale_attack_paths_scans_task

        result = cleanup_stale_attack_paths_scans_task.run()

        assert result == {"cleaned_up_count": 1, "scan_ids": ["scan-id"]}
        mock_cleanup.assert_called_once_with()


@pytest.mark.django_db
class TestAttackPathsDbUtilsActivity:
    @patch(
        "tasks.jobs.attack_paths.db_utils.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    def test_starting_scan_refreshes_updated_at(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import starting_attack_paths_scan

        old_updated_at = datetime.now(tz=UTC) - timedelta(hours=1)
        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider=aws_provider,
            scan=scans_fixture[0],
            state=StateChoices.SCHEDULED,
        )
        AttackPathsScan.objects.filter(id=attack_paths_scan.id).update(
            updated_at=old_updated_at
        )
        attack_paths_scan.refresh_from_db()

        started = starting_attack_paths_scan(
            attack_paths_scan, SimpleNamespace(update_tag=123)
        )

        assert attack_paths_scan.updated_at > old_updated_at
        attack_paths_scan.refresh_from_db()
        assert started is True
        assert attack_paths_scan.updated_at > old_updated_at

    @patch(
        "tasks.jobs.attack_paths.db_utils.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    def test_progress_update_refreshes_updated_at(
        self, tenants_fixture, aws_provider, scans_fixture
    ):
        from tasks.jobs.attack_paths.db_utils import update_attack_paths_scan_progress

        old_updated_at = datetime.now(tz=UTC) - timedelta(hours=1)
        attack_paths_scan = AttackPathsScan.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider=aws_provider,
            scan=scans_fixture[0],
            state=StateChoices.EXECUTING,
        )
        AttackPathsScan.objects.filter(id=attack_paths_scan.id).update(
            updated_at=old_updated_at
        )
        attack_paths_scan.refresh_from_db()

        update_attack_paths_scan_progress(attack_paths_scan, 42)

        assert attack_paths_scan.updated_at > old_updated_at
        attack_paths_scan.refresh_from_db()
        assert attack_paths_scan.progress == 42
        assert attack_paths_scan.updated_at > old_updated_at


@pytest.mark.django_db
class TestCleanupStaleAttackPathsScans:
    @pytest.fixture(autouse=True)
    def execute_on_commit_callbacks(self):
        with patch(
            "tasks.jobs.attack_paths.cleanup.on_commit",
            side_effect=lambda callback, **kwargs: callback(),
        ):
            yield

    def _create_executing_scan(
        self,
        tenant,
        provider,
        scan=None,
        started_at=None,
        updated_at=None,
        worker=None,
    ):
        """Helper to create an EXECUTING AttackPathsScan with optional Task+TaskResult."""
        ap_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=scan,
            state=StateChoices.EXECUTING,
            started_at=started_at or datetime.now(tz=UTC),
        )

        task_result = None
        if worker is not None:
            task_result = TaskResult.objects.create(
                task_id=str(ap_scan.id),
                task_name="attack-paths-scan-perform",
                status="STARTED",
                worker=worker,
            )
            task = Task.objects.create(
                id=task_result.task_id,
                task_runner_task=task_result,
                tenant_id=tenant.id,
            )
            ap_scan.task = task
            ap_scan.save(update_fields=["task_id"])

        if updated_at is not None:
            AttackPathsScan.objects.filter(id=ap_scan.id).update(updated_at=updated_at)
            ap_scan.updated_at = updated_at

        return ap_scan, task_result

    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    def test_defers_revoke_until_scan_failure_is_persisted(
        self,
        mock_revoke,
        tenants_fixture,
        aws_provider,
    ):
        from tasks.jobs.attack_paths.cleanup import _finalize_failed_scan

        ap_scan, task_result = self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            worker="unresponsive-worker@host",
        )

        with patch("tasks.jobs.attack_paths.cleanup.on_commit") as mock_on_commit:
            finalized_scan = _finalize_failed_scan(
                ap_scan,
                StateChoices.EXECUTING,
                "Cleanup reason",
                task_result=task_result,
                revoke=True,
            )

        assert finalized_scan is not None
        ap_scan.refresh_from_db()
        task_result.refresh_from_db()
        assert ap_scan.state == StateChoices.FAILED
        assert task_result.status == "FAILURE"
        mock_revoke.assert_not_called()
        mock_on_commit.assert_called_once()
        assert mock_on_commit.call_args.kwargs == {"using": DEFAULT_DB_ALIAS}

        callback = mock_on_commit.call_args.args[0]
        callback()

        mock_revoke.assert_called_once_with(task_result, terminate=True)

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_cleans_up_inactive_scan_with_unresponsive_worker(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans
        from tasks.jobs.attack_paths.db_utils import mark_scan_finished

        tenant = tenants_fixture[0]
        provider = aws_provider

        updated_at = datetime.now(tz=UTC) - timedelta(minutes=31)
        ap_scan, task_result = self._create_executing_scan(
            tenant,
            provider,
            updated_at=updated_at,
            worker="unresponsive-worker@host",
        )
        mock_ping.return_value = (set(), {"unresponsive-worker@host"})

        with patch(
            "tasks.jobs.attack_paths.cleanup.mark_scan_finished",
            wraps=mark_scan_finished,
        ) as mock_mark_failed:
            call_order = MagicMock()
            call_order.attach_mock(mock_revoke, "revoke")
            call_order.attach_mock(mock_mark_failed, "mark_failed")
            call_order.attach_mock(mock_drop_db, "drop_database")

            result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 1
        assert str(ap_scan.id) in result["scan_ids"]
        assert [entry[0] for entry in call_order.mock_calls] == [
            "mark_failed",
            "revoke",
            "drop_database",
        ]
        mock_revoke.assert_called_once_with(task_result, terminate=True)
        mock_drop_db.assert_called_once()
        mock_recover.assert_called_once()

        ap_scan.refresh_from_db()
        assert ap_scan.state == StateChoices.FAILED
        assert ap_scan.progress == 100
        assert ap_scan.completed_at is not None
        assert ap_scan.ingestion_exceptions == {
            "global_error": (
                "Worker unresponsive and scan inactive for 30 minutes - "
                "cleaned up by periodic task"
            )
        }

        task_result.refresh_from_db()
        assert task_result.status == "FAILURE"
        assert task_result.date_done is not None

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_revokes_and_cleans_scan_exceeding_threshold_on_responsive_worker(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        old_start = datetime.now(tz=UTC) - timedelta(hours=49)
        ap_scan, task_result = self._create_executing_scan(
            tenant, provider, started_at=old_start, worker="live-worker@host"
        )
        mock_ping.return_value = ({"live-worker@host"}, set())

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 1
        mock_revoke.assert_called_once_with(task_result, terminate=True)
        mock_recover.assert_called_once()

        ap_scan.refresh_from_db()
        assert ap_scan.state == StateChoices.FAILED

    @pytest.mark.parametrize(
        ("age_seconds", "should_clean"),
        [
            (960 * 60 - 1, False),
            (960 * 60, False),
            (960 * 60 + 1, True),
        ],
    )
    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_stale_threshold_boundary_is_strict(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        age_seconds,
        should_clean,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        now = datetime.now(tz=UTC)
        ap_scan, task_result = self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            started_at=now - timedelta(seconds=age_seconds),
            worker="live-worker@host",
        )
        mock_ping.return_value = ({"live-worker@host"}, set())

        with patch("tasks.jobs.attack_paths.cleanup.datetime") as mock_datetime:
            mock_datetime.now.return_value = now
            result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == int(should_clean)
        ap_scan.refresh_from_db()
        expected_state = StateChoices.FAILED if should_clean else StateChoices.EXECUTING
        assert ap_scan.state == expected_state
        if should_clean:
            mock_revoke.assert_called_once_with(task_result, terminate=True)
            mock_drop_db.assert_called_once()
            mock_recover.assert_called_once()
        else:
            mock_revoke.assert_not_called()
            mock_drop_db.assert_not_called()
            mock_recover.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_ignores_recent_executing_scans_on_responsive_worker(
        self,
        mock_ping,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        self._create_executing_scan(tenant, provider, worker="live-worker@host")
        mock_ping.return_value = ({"live-worker@host"}, set())

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0
        mock_drop_db.assert_not_called()
        mock_recover.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_preserves_recent_scan_on_unresponsive_worker(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=29),
            worker="unresponsive-worker@host",
        )
        mock_ping.return_value = (set(), {"unresponsive-worker@host"})

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0
        mock_revoke.assert_not_called()
        mock_drop_db.assert_not_called()
        mock_recover.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers", return_value=(set(), None))
    def test_final_ping_exception_preserves_pending_worker_scan(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        ap_scan, _ = self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            updated_at=datetime.now(tz=UTC) - timedelta(hours=1),
            worker="unknown-worker@host",
        )

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0
        mock_ping.assert_called_once_with({"unknown-worker@host"})
        ap_scan.refresh_from_db()
        assert ap_scan.state == StateChoices.EXECUTING
        mock_revoke.assert_not_called()
        mock_drop_db.assert_not_called()
        mock_recover.assert_not_called()

    @pytest.mark.parametrize(
        ("inactive_seconds", "should_clean"),
        [(29 * 60 + 59, False), (30 * 60, False), (30 * 60 + 1, True)],
    )
    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_inactivity_boundary_is_strict(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        inactive_seconds,
        should_clean,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        now = datetime.now(tz=UTC)
        ap_scan, task_result = self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            updated_at=now - timedelta(seconds=inactive_seconds),
            worker="unresponsive-worker@host",
        )
        mock_ping.return_value = (set(), {"unresponsive-worker@host"})

        with patch("tasks.jobs.attack_paths.cleanup.datetime") as mock_datetime:
            mock_datetime.now.return_value = now
            result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == int(should_clean)
        ap_scan.refresh_from_db()
        expected_state = StateChoices.FAILED if should_clean else StateChoices.EXECUTING
        assert ap_scan.state == expected_state
        if should_clean:
            mock_revoke.assert_called_once_with(task_result, terminate=True)
            mock_drop_db.assert_called_once()
            mock_recover.assert_called_once()
        else:
            mock_revoke.assert_not_called()
            mock_drop_db.assert_not_called()
            mock_recover.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    def test_ignores_completed_and_failed_scans(
        self,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            state=StateChoices.COMPLETED,
        )
        AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            state=StateChoices.FAILED,
        )

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0
        mock_drop_db.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch(
        "tasks.jobs.attack_paths.cleanup.graph_database.drop_database",
        side_effect=[Exception("Neo4j unreachable"), None],
    )
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    @patch("tasks.jobs.attack_paths.cleanup.logger")
    def test_neo4j_failure_leaves_scan_failed_and_continues(
        self,
        mock_logger,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        updated_at = datetime.now(tz=UTC) - timedelta(minutes=31)
        ap_scan_1, _ = self._create_executing_scan(
            tenant,
            provider,
            updated_at=updated_at,
            worker="unresponsive-worker-1@host",
        )
        ap_scan_2, _ = self._create_executing_scan(
            tenant,
            provider,
            updated_at=updated_at,
            worker="unresponsive-worker-2@host",
        )
        mock_ping.return_value = (
            set(),
            {"unresponsive-worker-1@host", "unresponsive-worker-2@host"},
        )

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 2
        assert mock_revoke.call_count == 2
        assert mock_drop_db.call_count == 2
        mock_logger.exception.assert_called_once()
        ap_scan_1.refresh_from_db()
        ap_scan_2.refresh_from_db()
        assert ap_scan_1.state == StateChoices.FAILED
        assert ap_scan_2.state == StateChoices.FAILED

    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch(
        "tasks.jobs.attack_paths.cleanup.mark_scan_finished",
        side_effect=DatabaseError("PostgreSQL unavailable"),
    )
    @patch("tasks.jobs.attack_paths.cleanup.logger")
    def test_postgresql_failure_prevents_revoke_and_neo4j_deletion(
        self,
        mock_logger,
        mock_mark_failed,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=31),
            worker="unresponsive-worker@host",
        )
        mock_ping.return_value = (set(), {"unresponsive-worker@host"})

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0
        mock_mark_failed.assert_called_once()
        mock_logger.exception.assert_called_once()
        mock_revoke.assert_not_called()
        mock_drop_db.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_cross_tenant_cleanup(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant1 = tenants_fixture[0]
        tenant2 = tenants_fixture[1]
        provider1 = aws_provider

        provider2 = Provider.objects.create(
            provider="aws",
            uid="999888777666",
            alias="aws_tenant2",
            tenant_id=tenant2.id,
        )

        updated_at = datetime.now(tz=UTC) - timedelta(minutes=31)
        ap_scan1, _ = self._create_executing_scan(
            tenant1,
            provider1,
            updated_at=updated_at,
            worker="unresponsive-worker-1@host",
        )
        ap_scan2, _ = self._create_executing_scan(
            tenant2,
            provider2,
            updated_at=updated_at,
            worker="unresponsive-worker-2@host",
        )
        mock_ping.return_value = (
            set(),
            {"unresponsive-worker-1@host", "unresponsive-worker-2@host"},
        )

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 2
        assert mock_revoke.call_count == 2
        assert mock_recover.call_count == 2

        ap_scan1.refresh_from_db()
        ap_scan2.refresh_from_db()
        assert ap_scan1.state == StateChoices.FAILED
        assert ap_scan2.state == StateChoices.FAILED

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_recovers_graph_data_ready_for_stale_scan(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        ap_scan, _ = self._create_executing_scan(
            tenant,
            provider,
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=31),
            worker="unresponsive-worker@host",
        )
        mock_ping.return_value = (set(), {"unresponsive-worker@host"})

        cleanup_stale_attack_paths_scans()

        mock_revoke.assert_called_once()
        mock_recover.assert_called_once()
        recovered_scan = mock_recover.call_args[0][0]
        assert recovered_scan.id == ap_scan.id

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    def test_fallback_to_time_heuristic_when_no_worker_field(
        self,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        # Old scan with no Task/TaskResult
        old_start = datetime.now(tz=UTC) - timedelta(hours=49)
        ap_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            state=StateChoices.EXECUTING,
            started_at=old_start,
        )

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 1

        ap_scan.refresh_from_db()
        assert ap_scan.state == StateChoices.FAILED

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_preserves_scans_without_a_started_at_timestamp(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        responsive_scan, _ = self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            worker="responsive-worker@host",
        )
        AttackPathsScan.objects.filter(id=responsive_scan.id).update(started_at=None)
        no_worker_scan = AttackPathsScan.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider=aws_provider,
            state=StateChoices.EXECUTING,
            started_at=None,
        )
        mock_ping.return_value = ({"responsive-worker@host"}, set())

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0
        responsive_scan.refresh_from_db()
        no_worker_scan.refresh_from_db()
        assert responsive_scan.state == StateChoices.EXECUTING
        assert no_worker_scan.state == StateChoices.EXECUTING
        mock_revoke.assert_not_called()
        mock_drop_db.assert_not_called()
        mock_recover.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    @patch("tasks.jobs.attack_paths.cleanup._ping_workers")
    def test_shared_worker_is_collected_only_once(
        self,
        mock_ping,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        updated_at = datetime.now(tz=UTC) - timedelta(minutes=31)
        self._create_executing_scan(
            tenant,
            provider,
            updated_at=updated_at,
            worker="shared-worker@host",
        )
        self._create_executing_scan(
            tenant,
            provider,
            updated_at=updated_at,
            worker="shared-worker@host",
        )
        mock_ping.return_value = (set(), {"shared-worker@host"})

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 2
        assert mock_revoke.call_count == 2
        mock_ping.assert_called_once_with({"shared-worker@host"})

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    def test_locked_recheck_preserves_scan_with_new_activity(
        self,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        ap_scan, _ = self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=31),
            worker="unresponsive-worker@host",
        )

        def record_activity(_workers):
            AttackPathsScan.objects.filter(id=ap_scan.id).update(
                updated_at=datetime.now(tz=UTC)
            )
            return set(), {"unresponsive-worker@host"}

        with patch(
            "tasks.jobs.attack_paths.cleanup._ping_workers",
            side_effect=record_activity,
        ):
            result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0
        ap_scan.refresh_from_db()
        assert ap_scan.state == StateChoices.EXECUTING
        mock_revoke.assert_not_called()
        mock_drop_db.assert_not_called()
        mock_recover.assert_not_called()

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    def test_locked_recheck_preserves_scan_that_changed_state(
        self,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
        scans_fixture,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        ap_scan, _ = self._create_executing_scan(
            tenants_fixture[0],
            aws_provider,
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=31),
            worker="unresponsive-worker@host",
        )

        def complete_scan(_workers):
            AttackPathsScan.objects.filter(id=ap_scan.id).update(
                state=StateChoices.COMPLETED
            )
            return set(), {"unresponsive-worker@host"}

        with patch(
            "tasks.jobs.attack_paths.cleanup._ping_workers",
            side_effect=complete_scan,
        ):
            result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0
        ap_scan.refresh_from_db()
        assert ap_scan.state == StateChoices.COMPLETED
        mock_revoke.assert_not_called()
        mock_drop_db.assert_not_called()
        mock_recover.assert_not_called()

    # `SCHEDULED` state cleanup
    def _create_scheduled_scan(
        self,
        tenant,
        provider,
        *,
        age_minutes,
        parent_state,
        with_task=True,
    ):
        """Create a SCHEDULED AttackPathsScan with a parent Scan in `parent_state`.

        `age_minutes` controls how far in the past `started_at` is set, so
        callers can place rows safely past the cleanup cutoff.
        """
        parent_scan = Scan.objects.create(
            name="Parent Prowler scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=parent_state,
            tenant_id=tenant.id,
        )

        ap_scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            scan=parent_scan,
            state=StateChoices.SCHEDULED,
            started_at=datetime.now(tz=UTC) - timedelta(minutes=age_minutes),
        )

        task_result = None
        if with_task:
            task_result = TaskResult.objects.create(
                task_id=str(ap_scan.id),
                task_name="attack-paths-scan-perform",
                status="PENDING",
            )
            task = Task.objects.create(
                id=task_result.task_id,
                task_runner_task=task_result,
                tenant_id=tenant.id,
            )
            ap_scan.task = task
            ap_scan.save(update_fields=["task_id"])

        return ap_scan, task_result

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    def test_cleans_up_scheduled_scan_when_parent_is_terminal(
        self,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        ap_scan, task_result = self._create_scheduled_scan(
            tenant,
            provider,
            age_minutes=24 * 60 * 3,  # 3 days, safely past any threshold
            parent_state=StateChoices.FAILED,
        )

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 1
        assert str(ap_scan.id) in result["scan_ids"]

        ap_scan.refresh_from_db()
        assert ap_scan.state == StateChoices.FAILED
        assert ap_scan.progress == 100
        assert ap_scan.completed_at is not None
        assert ap_scan.ingestion_exceptions == {
            "global_error": "Scan never started - cleaned up by periodic task"
        }

        # SCHEDULED revoke must NOT terminate a running worker
        mock_revoke.assert_called_once()
        assert mock_revoke.call_args.kwargs == {"terminate": False}

        # Temp DB never created for SCHEDULED, so no drop attempted
        mock_drop_db.assert_not_called()
        # Tenant Neo4j data is untouched in this path
        mock_recover.assert_not_called()

        task_result.refresh_from_db()
        assert task_result.status == "FAILURE"
        assert task_result.date_done is not None

    @patch("tasks.jobs.attack_paths.cleanup.recover_graph_data_ready")
    @patch("tasks.jobs.attack_paths.cleanup.graph_database.drop_database")
    @patch(
        "tasks.jobs.attack_paths.cleanup.rls_transaction",
        new=lambda *args, **kwargs: nullcontext(),
    )
    @patch("tasks.jobs.attack_paths.cleanup._revoke_task")
    def test_skips_scheduled_scan_when_parent_still_in_flight(
        self,
        mock_revoke,
        mock_drop_db,
        mock_recover,
        tenants_fixture,
        aws_provider,
    ):
        from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

        tenant = tenants_fixture[0]
        provider = aws_provider

        ap_scan, _ = self._create_scheduled_scan(
            tenant,
            provider,
            age_minutes=24 * 60 * 3,
            parent_state=StateChoices.EXECUTING,
        )

        result = cleanup_stale_attack_paths_scans()

        assert result["cleaned_up_count"] == 0

        ap_scan.refresh_from_db()
        assert ap_scan.state == StateChoices.SCHEDULED
        mock_revoke.assert_not_called()


class TestNormalizeSinkProperties:
    """Coerce Cartography-emitted property values into sink-portable primitives.

    Lists become comma-strings, dicts become JSON strings, temporals become
    ISO strings, spatials become their stringified form. The same coercion
    runs regardless of the active sink so queries are portable.
    """

    @pytest.mark.parametrize(
        "raw, expected",
        [
            (
                {"a": "x", "b": 1, "c": 1.5, "d": True, "e": None},
                {"a": "x", "b": 1, "c": 1.5, "d": True, "e": None},
            ),
            (
                {"actions": ["s3:GetObject", "s3:PutObject"], "tags": []},
                {"actions": "s3:GetObject,s3:PutObject", "tags": ""},
            ),
            (
                {"condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}}},
                {
                    "condition": '{"StringEquals": {"aws:SourceAccount": "123456789012"}}'
                },
            ),
        ],
    )
    def test_primitive_list_and_dict_branches(self, raw, expected):
        sync_module._normalize_sink_properties(raw, labels=None)
        assert raw == expected

    def test_temporal_and_spatial_become_strings(self):
        class FakeDateTime:
            def iso_format(self) -> str:
                return "2026-05-13T10:00:00+00:00"

        class FakeSpatialPoint:
            def __str__(self) -> str:
                return "POINT(1.0 2.0)"

        # The spatial branch is detected by module prefix, not by base class.
        FakeSpatialPoint.__module__ = "neo4j.spatial.fake"

        props = {
            "created_at": FakeDateTime(),
            "location": FakeSpatialPoint(),
        }
        sync_module._normalize_sink_properties(props, labels=None)
        assert props == {
            "created_at": "2026-05-13T10:00:00+00:00",
            "location": "POINT(1.0 2.0)",
        }
