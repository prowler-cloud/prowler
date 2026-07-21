from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import neo4j.exceptions
import pytest
from tasks.jobs.attack_paths import aws

DATABASE_NOT_FOUND_CODE = "Neo.ClientError.Database.DatabaseNotFound"


def _make_neo4j_error(code: str) -> neo4j.exceptions.Neo4jError:
    return neo4j.exceptions.Neo4jError._hydrate_neo4j(
        code=code,
        message="graph query failed",
    )


def _resource_functions(failing_sync, following_sync):
    return {
        "failing_sync": failing_sync,
        "following_sync": following_sync,
        "permission_relationships": MagicMock(),
        "resourcegroupstaggingapi": MagicMock(),
    }


def test_sync_aws_account_reraises_database_not_found_immediately():
    error = _make_neo4j_error(DATABASE_NOT_FOUND_CODE)
    failing_sync = MagicMock(side_effect=error)
    following_sync = MagicMock()

    with (
        patch.object(
            aws.cartography_aws,
            "RESOURCE_FUNCTIONS",
            _resource_functions(failing_sync, following_sync),
        ),
        patch.object(aws.db_utils, "update_attack_paths_scan_progress"),
        patch.object(aws.utils, "stringify_exception") as stringify_exception,
        patch.object(aws.logger, "warning") as warning,
        pytest.raises(neo4j.exceptions.Neo4jError) as exc_info,
    ):
        aws.sync_aws_account(
            SimpleNamespace(uid="123456789012"),
            [
                "failing_sync",
                "following_sync",
                "permission_relationships",
                "resourcegroupstaggingapi",
            ],
            {},
            MagicMock(),
        )

    assert exc_info.value is error
    following_sync.assert_not_called()
    stringify_exception.assert_not_called()
    warning.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        _make_neo4j_error("Neo.ClientError.Statement.SyntaxError"),
        RuntimeError("resource sync failed"),
    ],
    ids=["different-neo4j-error", "non-neo4j-error"],
)
def test_sync_aws_account_warns_and_continues_for_other_exceptions(error):
    failing_sync = MagicMock(side_effect=error)
    following_sync = MagicMock()

    with (
        patch.object(
            aws.cartography_aws,
            "RESOURCE_FUNCTIONS",
            _resource_functions(failing_sync, following_sync),
        ),
        patch.object(aws.db_utils, "update_attack_paths_scan_progress"),
        patch.object(
            aws.utils,
            "stringify_exception",
            return_value="formatted failure",
        ),
        patch.object(aws.logger, "warning") as warning,
    ):
        failed_syncs = aws.sync_aws_account(
            SimpleNamespace(uid="123456789012"),
            [
                "failing_sync",
                "following_sync",
                "permission_relationships",
                "resourcegroupstaggingapi",
            ],
            {},
            MagicMock(),
        )

    assert failed_syncs == {"failing_sync": "formatted failure"}
    following_sync.assert_called_once_with()
    warning.assert_called_once()
    assert "Continuing to the next AWS sync function" in warning.call_args.args[0]
