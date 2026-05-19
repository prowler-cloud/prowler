"""Fail-driven per-service resource scan limit.

Some AWS services accumulate huge numbers of resources (EBS snapshots, backup
recovery points, log groups, Lambda functions, ECS task definitions,
CodeArtifact packages). Scanning all of them causes API throttling, slow
scans, cost and noisy findings.

``limited_findings`` lets a check consume resources lazily and stop pulling
the iterator as soon as the FAIL quota is met, while **never hiding a FAIL**
before a PASS. The limit is configurable per service via the Prowler config
file (see ``get_resource_scan_limit``).
"""

from typing import Any, Callable, Iterable, List, Optional

GLOBAL_LIMIT_KEY = "max_scanned_resources_per_service"
DEFAULT_RESOURCE_SCAN_LIMIT = 100


def get_resource_scan_limit(audit_config: dict, service_key: str) -> Optional[int]:
    """Resolve the resource scan limit for a service.

    Precedence: per-service key (``service_key``) > global
    ``max_scanned_resources_per_service`` > default (100).

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
        value = audit_config.get(GLOBAL_LIMIT_KEY, DEFAULT_RESOURCE_SCAN_LIMIT)
    if value is None or value <= 0:
        return None
    return int(value)


def limited_findings(
    resource_iter: Iterable[Any],
    evaluate: Callable[[Any], Optional[Any]],
    limit: Optional[int],
) -> List[Any]:
    """Evaluate resources lazily, prioritizing FAIL findings within ``limit``.

    The iterator is pulled lazily and consumption stops as soon as ``limit``
    FAIL findings are collected, which bounds the underlying API calls in
    noisy accounts. When ``limit`` is not reached, FAIL and PASS findings are
    summed (FAIL first). When ``limit`` is ``None`` or non-positive, every
    resource is evaluated (legacy behavior).

    Args:
        resource_iter: Lazy iterable of resources to evaluate.
        evaluate: Per-resource callback returning a finding (with a ``status``
            attribute of ``"FAIL"``/``"PASS"``) or ``None`` to skip.
        limit: Maximum number of findings to return, or ``None`` for no limit.

    Returns:
        The list of findings, FAIL findings first.
    """
    if not limit or limit <= 0:
        return [
            report
            for report in (evaluate(resource) for resource in resource_iter)
            if report is not None
        ]

    fails: List[Any] = []
    passes: List[Any] = []
    for resource in resource_iter:
        report = evaluate(resource)
        if report is None:
            continue
        if report.status == "FAIL":
            fails.append(report)
            if len(fails) >= limit:
                # FAIL quota full: stop pulling the iterator (lazy fetch stops)
                break
        elif len(passes) < limit:
            passes.append(report)

    if len(fails) >= limit:
        return fails[:limit]
    return fails + passes[: max(0, limit - len(fails))]
