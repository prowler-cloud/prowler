from typing import Any, Iterable, Optional, Tuple, Union

from prowler.providers.aws.services.ec2.lib.security_groups import _is_cidr_public

HOST_TRUST_MODEL_BOILERPLATE = (
    "This finding concerns the workload host environment. The isolation "
    "guarantees of any Nitro Enclave running on this instance are "
    "independent of this finding."
)

# Threshold at which the unrestricted-ingress check summarizes a wide
# non-allow-listed port range as ``from-to`` instead of enumerating every
# port. Keeps the FAIL message actionable when a rule like ``0-65535`` is
# hit without truncating small offenders like ``[8080]``.
UNRESTRICTED_INGRESS_SUMMARY_THRESHOLD = 10


def is_enclave_parent(instance: Any) -> bool:
    """Return True when this EC2 instance is a candidate parent for a Nitro Enclave.

    Instances in pending, shutting-down, or terminated states are skipped so
    checks do not report on lifecycle-transient resources (per RFC edge cases).

    Args:
        instance: An EC2 ``Instance`` model exposing ``enclaves_enabled`` and
            ``state`` attributes.

    Returns:
        bool: True when the instance has enclaves enabled and is not in a
        lifecycle-transient state.
    """
    return bool(
        getattr(instance, "enclaves_enabled", False)
    ) and instance.state not in {
        "pending",
        "shutting-down",
        "terminated",
    }


def rule_world_facing_port_range(
    rule: dict, protocols: Iterable[str] = ("tcp",)
) -> Optional[Union[str, Tuple[int, int]]]:
    """Return the port range this ingress rule exposes to the world.

    "The world" is any globally routable CIDR: exact ``0.0.0.0/0`` and
    ``::/0`` plus supernets such as ``0.0.0.0/1``, ``128.0.0.0/1``, ``::/1``,
    ``8000::/1`` which also reach the public Internet. Detection delegates
    to ``security_groups._is_cidr_public`` so the semantics match every
    other Prowler check.

    ``protocols`` lists the L4 protocols the caller wants to track (``tcp``
    by default; pass ``("tcp", "udp")`` to also flag UDP ingress). The
    all-protocol ``-1`` always returns ``"all"`` because it covers every
    protocol, including whatever ``protocols`` requests.

    Args:
        rule: A boto3 ingress rule dict with ``IpProtocol``, ``IpRanges``,
            ``Ipv6Ranges``, ``FromPort`` and ``ToPort`` keys.
        protocols: L4 protocols to evaluate. Defaults to ``("tcp",)``.

    Returns:
        Optional[Union[str, Tuple[int, int]]]:
            - ``"all"`` when the rule opens every port (``IpProtocol="-1"``
              or a tracked protocol on ``0-65535``).
            - ``(from_port, to_port)`` for a specific tracked-protocol range.
            - ``None`` when the rule does not expose anything to the public
              Internet, is for a protocol not in ``protocols``, or is
              missing port bounds.
    """
    ip_ranges = rule.get("IpRanges") or []
    ipv6_ranges = rule.get("Ipv6Ranges") or []
    world_facing = any(
        isinstance(r.get("CidrIp"), str) and _is_cidr_public(r["CidrIp"])
        for r in ip_ranges
    ) or any(
        isinstance(r.get("CidrIpv6"), str) and _is_cidr_public(r["CidrIpv6"])
        for r in ipv6_ranges
    )
    if not world_facing:
        return None

    protocol = rule.get("IpProtocol")
    if protocol == "-1":
        return "all"
    if protocol not in protocols:
        return None

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    if from_port is None or to_port is None:
        return None
    if from_port == 0 and to_port == 65535:
        return "all"
    return (from_port, to_port)
