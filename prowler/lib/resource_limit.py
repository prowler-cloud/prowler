"""Scoped resource scan limits for high-volume resources.

Some services accumulate huge numbers of resources (EBS snapshots, backup
recovery points, log groups, Lambda functions, ECS task definitions,
CodeArtifact packages). Scanning all of them causes API throttling, slow
scans, cost and noisy findings.

``get_resource_scan_limit`` resolves the configured number of resources to
analyze for a supported resource path. A limited resource can produce zero,
one, or many findings; findings are not capped or re-ordered here.

Tradeoff: for newest-based resources, services may need to list lightweight or
base metadata broadly to select the truly newest resources, then apply limits
only to expensive hydration or analysis. The helper must not send
user-configured limits as unsafe paginator ``PageSize`` values because AWS
services validate page sizes differently.
"""

from collections.abc import Callable, Iterable, Iterator, Mapping
from itertools import islice
from typing import Any, Optional, Protocol, TypeVar

GLOBAL_LIMIT_KEY = "max_scanned_resources_per_service"
T = TypeVar("T")


class PaginatorProtocol(Protocol):
    """Minimal boto3-compatible paginator interface used by this module."""

    def paginate(self, **operation_parameters: Any) -> Iterable[Mapping[str, Any]]:
        """Return paginator pages for the provided operation parameters."""


def get_resource_scan_limit(audit_config: dict, service_key: str) -> Optional[int]:
    """Resolve the resource scan limit for a service.

    Precedence: per-service key (``service_key``) > global
    ``max_scanned_resources_per_service`` > unlimited.

    A non-positive resolved value means **unlimited** (``None``), preserving
    the legacy behavior as an explicit opt-out.

    Args:
        audit_config: The provider ``audit_config`` dictionary.
        service_key: The per-service config key, e.g. ``max_lambda_functions``.

    Returns:
        The limit as a positive ``int``, or ``None`` for unlimited.
    """
    value = audit_config.get(service_key)
    if value is None:
        value = audit_config.get(GLOBAL_LIMIT_KEY)
    if value is None or value <= 0:
        return None
    return int(value)


def limit_resources(resources: Iterable[T], limit: Optional[int]) -> Iterator[T]:
    """Yield up to ``limit`` resources without changing resource order."""
    if not limit or limit <= 0:
        yield from resources
        return
    yield from islice(resources, limit)


def iter_limited_paginator_items(
    paginator: PaginatorProtocol,
    result_key: str,
    limit: Optional[int],
    item_filter: Optional[Callable[[T], bool]] = None,
    **operation_parameters: Any,
) -> Iterator[T]:
    """Yield paginator result items, stopping after ``limit`` selected items.

    The configured resource-analysis limit is intentionally not sent as
    ``PageSize`` because AWS services validate page sizes differently. The
    paginator receives only the operation parameters needed by the AWS API,
    while this iterator applies the analysis limit defensively client-side.
    """
    selected = 0
    for page in paginator.paginate(**operation_parameters):
        for item in page.get(result_key, []):
            if item_filter and not item_filter(item):
                continue
            yield item
            selected += 1
            if limit and selected >= limit:
                return
