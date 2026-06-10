"""Scoped resource scan limits for high-volume AWS resources.

Some AWS services accumulate huge numbers of resources (EBS snapshots, backup
recovery points, log groups, Lambda functions, ECS task definitions,
CodeArtifact packages). Scanning all of them causes API throttling, slow
scans, cost and noisy findings.

``get_resource_scan_limit`` resolves the configured number of resources to
analyze for a supported resource path. A limited resource can produce zero,
one, or many findings; findings are not capped or re-ordered here.
"""

from collections.abc import Iterable, Iterator
from itertools import islice
from typing import Optional, TypeVar

GLOBAL_LIMIT_KEY = "max_scanned_resources_per_service"
T = TypeVar("T")


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
