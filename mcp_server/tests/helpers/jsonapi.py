"""Builders for the JSON:API documents the Prowler API returns.

Every model's ``from_api_response()`` and every tool's error path consumes one of
these shapes, so building them by hand in each test would duplicate the document
structure hundreds of times. The builders keep the *shape* in one place so tests
only express the part they actually care about.
"""

from typing import Any


def jsonapi_relationship_many(resource_type: str, *ids: str) -> dict[str, Any]:
    """Build a to-many relationship.

    Passing no ids yields a present-but-empty relationship (``{"data": []}``),
    which ``extract_relationship_ids`` reports as ``[]`` rather than ``None``.
    """
    return {"data": [{"type": resource_type, "id": resource_id} for resource_id in ids]}


def jsonapi_relationship_one(resource_type: str, resource_id: str) -> dict[str, Any]:
    """Build a to-one relationship."""
    return {"data": {"type": resource_type, "id": resource_id}}


def jsonapi_resource(
    resource_type: str,
    resource_id: str,
    attributes: dict[str, Any] | None = None,
    relationships: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a single JSON:API resource object.

    ``relationships`` is omitted from the result entirely when not supplied, so a
    test can express "the document did not expose this relationship"
    (``extract_relationship_ids`` -> ``None``) distinctly from "the relationship
    is present and empty" (-> ``[]``). Conflating the two is exactly the bug the
    models go out of their way to avoid.
    """
    resource: dict[str, Any] = {
        "type": resource_type,
        "id": resource_id,
        "attributes": attributes or {},
    }
    if relationships is not None:
        resource["relationships"] = relationships
    return resource


def jsonapi_document(
    data: dict[str, Any] | list[dict[str, Any]],
    included: list[dict[str, Any]] | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a top-level JSON:API document."""
    document: dict[str, Any] = {"data": data}
    if included is not None:
        document["included"] = included
    if meta is not None:
        document["meta"] = meta
    return document


def jsonapi_collection(
    items: list[dict[str, Any]],
    *,
    page: int = 1,
    pages: int = 1,
    count: int | None = None,
    included: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a paginated collection document.

    The ``meta.pagination`` keys are exactly the ones every ``*ListResponse``
    reads (``page``, ``pages``, ``count``). ``count`` defaults to the number of
    items so the common single-page case needs no arguments.
    """
    return jsonapi_document(
        data=items,
        included=included,
        meta={
            "pagination": {
                "page": page,
                "pages": pages,
                "count": len(items) if count is None else count,
            }
        },
    )


def jsonapi_error(status: int, detail: str, title: str | None = None) -> dict[str, Any]:
    """Build an error document.

    ``ProwlerAPIClient._make_request`` surfaces ``errors[0].detail`` in the
    exception message it raises, and tools relay that straight to the model.
    """
    error: dict[str, Any] = {"status": str(status), "detail": detail}
    if title is not None:
        error["title"] = title
    return {"errors": [error]}


def task_document(task_id: str, state: str, error: str | None = None) -> dict[str, Any]:
    """Build a ``/tasks/{id}`` document for driving ``poll_task_until_complete``.

    Register a sequence of these on a ``MockRouter`` route (for example
    ``executing``, ``executing``, ``completed``) to exercise the polling loop.
    """
    attributes: dict[str, Any] = {"state": state}
    if error is not None:
        attributes["error"] = error
    return jsonapi_document(jsonapi_resource("tasks", task_id, attributes))
