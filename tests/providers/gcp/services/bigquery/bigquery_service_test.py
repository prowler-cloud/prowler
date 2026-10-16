from unittest.mock import MagicMock, patch

from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestBigQueryService:
    def test_service(self):
        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            bigquery_client = BigQuery(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert bigquery_client.service == "bigquery"
            assert bigquery_client.project_ids == [GCP_PROJECT_ID]

            assert len(bigquery_client.datasets) == 2

            assert bigquery_client.datasets[0].name == "unique_dataset1_name"
            assert bigquery_client.datasets[0].id.__class__.__name__ == "str"
            assert bigquery_client.datasets[0].region == "US"
            assert bigquery_client.datasets[0].cmk_encryption
            assert bigquery_client.datasets[0].public
            assert bigquery_client.datasets[0].project_id == GCP_PROJECT_ID

            assert bigquery_client.datasets[1].name == "unique_dataset2_name"
            assert bigquery_client.datasets[1].id.__class__.__name__ == "str"
            assert bigquery_client.datasets[1].region == "EU"
            assert not bigquery_client.datasets[1].cmk_encryption
            assert not bigquery_client.datasets[1].public
            assert bigquery_client.datasets[1].project_id == GCP_PROJECT_ID

            assert len(bigquery_client.tables) == 2

            assert bigquery_client.tables[0].name == "unique_table1_name"
            assert bigquery_client.tables[0].id.__class__.__name__ == "str"
            assert bigquery_client.tables[0].region == "US"
            assert bigquery_client.tables[0].cmk_encryption
            assert bigquery_client.tables[0].project_id == GCP_PROJECT_ID

            assert bigquery_client.tables[1].name == "unique_table2_name"
            assert bigquery_client.tables[1].id.__class__.__name__ == "str"
            assert bigquery_client.tables[1].region == "US"
            assert not bigquery_client.tables[1].cmk_encryption
            assert bigquery_client.tables[1].project_id == GCP_PROJECT_ID


def _mocked_client(dataset_ids, tables_by_dataset, failing_table_ids=()):
    """A BigQuery discovery client returning the given datasets and tables.

    Purpose-built rather than extending the shared fixture so these tests can
    control table counts and provoke per-table failures.
    """
    client = MagicMock()

    datasets = client.datasets.return_value
    datasets.list.return_value.execute.return_value = {
        "datasets": [
            {
                "datasetReference": {"datasetId": d},
                "id": f"project:{d}",
                "location": "EU",
            }
            for d in dataset_ids
        ]
    }
    datasets.list_next.return_value = None
    datasets.get.side_effect = lambda projectId, datasetId: MagicMock(
        execute=MagicMock(return_value={"access": []})
    )

    tables = client.tables.return_value
    tables.list.side_effect = lambda projectId, datasetId: MagicMock(
        execute=MagicMock(
            return_value={
                "tables": [
                    {"tableReference": {"tableId": t}, "id": f"project:{datasetId}.{t}"}
                    for t in tables_by_dataset[datasetId]
                ]
            }
        )
    )
    tables.list_next.return_value = None

    def _get_table(projectId, datasetId, tableId):
        if tableId in failing_table_ids:
            raise RuntimeError(f"boom for {tableId}")
        return MagicMock(execute=MagicMock(return_value={}))

    tables.get.side_effect = _get_table
    return client


def _bigquery_with(client):
    with (
        patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ),
        patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=lambda *_args, **_kwargs: client,
        ),
    ):
        return BigQuery(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))


class TestBigQueryConcurrentEnumeration:
    def test_table_order_follows_listing_order(self):
        """Tables are described concurrently but must land in listing order.

        Without this the service's output would vary run to run, which the
        assertions in TestBigQueryService depend on and pytest-randomly would
        eventually expose.
        """
        tables_by_dataset = {
            "dataset_a": [f"a_table_{i:03d}" for i in range(60)],
            "dataset_b": [f"b_table_{i:03d}" for i in range(40)],
        }
        client = _mocked_client(["dataset_a", "dataset_b"], tables_by_dataset)
        bigquery_client = _bigquery_with(client)

        expected = tables_by_dataset["dataset_a"] + tables_by_dataset["dataset_b"]
        assert [t.name for t in bigquery_client.tables] == expected

    def test_one_unreadable_table_does_not_drop_the_rest(self):
        """A failing tables.get must not abandon the remaining tables."""
        tables_by_dataset = {"dataset_a": [f"t{i}" for i in range(10)]}
        client = _mocked_client(
            ["dataset_a"], tables_by_dataset, failing_table_ids={"t4"}
        )
        bigquery_client = _bigquery_with(client)

        names = [t.name for t in bigquery_client.tables]
        assert "t4" not in names
        assert names == [f"t{i}" for i in range(10) if i != 4]

    def test_http_clients_are_per_thread_not_per_request(self):
        """googleapiclient's http is not thread safe, so each worker needs its own.

        Building one per request would mean a TLS handshake per table; the count
        must stay bounded by the worker pool no matter how many tables there are.
        """
        from prowler.providers.gcp.services.bigquery import bigquery_service

        created = []

        def _counting_http(self):
            created.append(1)
            return MagicMock()

        tables_by_dataset = {"dataset_a": [f"t{i:03d}" for i in range(200)]}
        client = _mocked_client(["dataset_a"], tables_by_dataset)

        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__get_AuthorizedHttp_client__",
            new=_counting_http,
        ):
            bigquery_client = _bigquery_with(client)

        assert len(bigquery_client.tables) == 200
        # At least one: the threaded path must pass an explicit http, or it is
        # sharing the client's non-thread-safe one.
        assert created, "no per-thread http was created; execute() shares the client's"
        assert len(created) <= bigquery_service.MAX_WORKERS

    def test_http_clients_stay_bounded_across_projects_and_phases(self):
        """The bound must hold across every project and both enumeration phases.

        A pool opened per project, or a second pool for tables, spawns fresh
        threads and therefore fresh thread-local http clients, so the ceiling
        would scale with the project count instead of staying at MAX_WORKERS.
        """
        from prowler.providers.gcp.services.bigquery import bigquery_service

        created = []

        def _counting_http(self):
            created.append(1)
            return MagicMock()

        tables_by_dataset = {"dataset_a": [f"t{i:03d}" for i in range(60)]}
        client = _mocked_client(["dataset_a"], tables_by_dataset)

        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__get_AuthorizedHttp_client__",
            new=_counting_http,
        ):
            with (
                patch(
                    "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                    new=mock_is_api_active,
                ),
                patch(
                    "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                    new=lambda *_args, **_kwargs: client,
                ),
            ):
                BigQuery(
                    set_mocked_gcp_provider(
                        project_ids=[GCP_PROJECT_ID, "second-project", "third-project"]
                    )
                )

        assert created, "no per-thread http was created"
        assert len(created) <= bigquery_service.MAX_WORKERS, (
            f"created {len(created)} http clients across 3 projects; "
            f"expected at most {bigquery_service.MAX_WORKERS}"
        )

    def test_concurrent_workers_receive_distinct_http_clients(self):
        """Bounding the client count is not enough; workers must not share one.

        A single globally cached AuthorizedHttp would satisfy the upper-bound
        assertion above with created == 1 while still handing the same
        non-thread-safe object to every worker. This forces two describe calls
        to overlap and checks they hold different clients.
        """
        import threading

        seen = {}
        overlap = threading.Barrier(2, timeout=10)

        client = _mocked_client(
            ["dataset_a"], {"dataset_a": [f"t{i}" for i in range(8)]}
        )

        def _execute(http=None, num_retries=None):
            seen.setdefault(threading.get_ident(), []).append(id(http))
            try:
                overlap.wait()
            except threading.BrokenBarrierError:
                pass
            return {}

        client.tables.return_value.get.side_effect = (
            lambda projectId, datasetId, tableId: MagicMock(execute=_execute)
        )

        _bigquery_with(client)

        assert len(seen) >= 2, (
            f"expected at least two concurrent workers, saw {len(seen)} thread(s)"
        )
        per_thread = {tid: set(ids) for tid, ids in seen.items()}
        for tid, ids in per_thread.items():
            assert len(ids) == 1, (
                f"thread {tid} used {len(ids)} http clients, expected 1"
            )
        distinct = {next(iter(ids)) for ids in per_thread.values()}
        assert len(distinct) == len(per_thread), (
            "concurrent workers shared an http client; googleapiclient's http is "
            "not thread safe"
        )
