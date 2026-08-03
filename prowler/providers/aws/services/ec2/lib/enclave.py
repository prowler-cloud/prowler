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


def is_enclave_parent(instance) -> bool:
    """Return True when this EC2 instance is a candidate parent for a Nitro Enclave.

    Instances in pending, shutting-down, or terminated states are skipped so
    checks do not report on lifecycle-transient resources (per RFC edge cases).
    """
    return bool(
        getattr(instance, "enclaves_enabled", False)
    ) and instance.state not in {
        "pending",
        "shutting-down",
        "terminated",
    }


def rule_world_facing_port_range(rule, protocols=("tcp",)):
    """Return the port range this ingress rule exposes to the world.

    "The world" means ``0.0.0.0/0`` (IPv4) or ``::/0`` (IPv6). ``protocols``
    lists the L4 protocols the caller wants to track (``tcp`` by default;
    pass ``("tcp", "udp")`` to also flag UDP ingress). The all-protocol
    ``-1`` always returns ``"all"`` because it covers every protocol,
    including whatever ``protocols`` requests.

    Returns:
        - ``"all"`` when the rule opens every port (``IpProtocol="-1"`` or
          a tracked protocol on ``0-65535``).
        - ``(from_port, to_port)`` for a specific tracked-protocol range.
        - ``None`` when the rule does not expose anything to the world, is
          for a protocol not in ``protocols``, or is missing port bounds.
    """
    ip_ranges = rule.get("IpRanges") or []
    ipv6_ranges = rule.get("Ipv6Ranges") or []
    world_facing = any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges) or any(
        r.get("CidrIpv6") == "::/0" for r in ipv6_ranges
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
