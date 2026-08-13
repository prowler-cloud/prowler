"""Shared test helpers for the Prowler MCP Server suite.

Import from the submodules directly (``from tests.helpers.jsonapi import ...``);
this package only re-exports the surface so it is discoverable in one place.

Nothing here is collected by pytest -- ``python_files`` is ``test_*.py``.
"""

from tests.helpers.assertions import (
    NAMESPACES,
    assert_namespaced,
    assert_tool_contract,
    tools_in_namespace,
)
from tests.helpers.http import MockRouter
from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_document,
    jsonapi_error,
    jsonapi_relationship_many,
    jsonapi_relationship_one,
    jsonapi_resource,
    task_document,
)
from tests.helpers.tokens import (
    FAKE_API_KEY,
    FAKE_LEGACY_API_KEY,
    MALFORMED_API_KEY,
    fake_jwt,
)

__all__ = [
    "FAKE_API_KEY",
    "FAKE_LEGACY_API_KEY",
    "MALFORMED_API_KEY",
    "NAMESPACES",
    "MockRouter",
    "assert_namespaced",
    "assert_tool_contract",
    "fake_jwt",
    "jsonapi_collection",
    "jsonapi_document",
    "jsonapi_error",
    "jsonapi_relationship_many",
    "jsonapi_relationship_one",
    "jsonapi_resource",
    "task_document",
    "tools_in_namespace",
]
