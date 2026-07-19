from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass

MIN_PORT = 0
MAX_PORT = 65535
ALL_PORTS_RANGE = "-1/-1"
PUBLIC_SOURCE_FIELDS = ("source_cidr_ip", "ipv_6source_cidr_ip")


@dataclass(frozen=True)
class EffectiveRule:
    """Normalized public ingress rule used for priority evaluation.

    Attributes:
        policy: Normalized Accept or Drop policy.
        priority: Rule priority, where lower numbers take precedence.
        from_port: Inclusive lower port boundary.
        to_port: Inclusive upper port boundary.
    """

    policy: str
    priority: int
    from_port: int
    to_port: int


def is_public_cidr(cidr: str) -> bool:
    """Return True when the CIDR represents public/unrestricted access."""
    return cidr in ("0.0.0.0/0", "::/0")


def port_in_range(port_range: str, target_port: int) -> bool:
    """
    Check if target_port is within the provided port range.

    Port range examples:
    - "3389/3389" -> single port range
    - "22" -> single port
    """
    if not port_range or not MIN_PORT <= target_port <= MAX_PORT:
        return False

    try:
        if "/" in port_range:
            range_parts = port_range.split("/")
            if len(range_parts) != 2:
                return False
            from_port, to_port = map(int, range_parts)
            if from_port == -1 and to_port == -1:
                return False
            if not (
                MIN_PORT <= from_port <= MAX_PORT and MIN_PORT <= to_port <= MAX_PORT
            ):
                return False
            return from_port <= target_port <= to_port
        port = int(port_range)
        return MIN_PORT <= port <= MAX_PORT and port == target_port
    except (ValueError, AttributeError):
        return False


def _parse_priority(ingress_rule: Mapping[str, object]) -> int | None:
    """Parse an Alibaba rule priority, where lower numbers take precedence.

    Args:
        ingress_rule: Raw ingress rule from the ECS API.

    Returns:
        A priority from 1 through 100, defaulting to 1 when omitted, or None
        when an explicit value is malformed.
    """
    if "priority" not in ingress_rule:
        return 1
    priority = ingress_rule["priority"]
    if isinstance(priority, bool):
        return None
    try:
        parsed_priority = int(priority)
    except (TypeError, ValueError):
        return None
    return parsed_priority if 1 <= parsed_priority <= 100 else None


def _parse_effective_rule(
    ingress_rule: Mapping[str, object], source_field: str
) -> EffectiveRule | None:
    """Normalize a public TCP or all-protocol rule for one address family.

    Args:
        ingress_rule: Raw ingress rule from the ECS API.
        source_field: IPv4 or IPv6 source field to evaluate.

    Returns:
        The normalized rule, or None when it cannot affect public exposure.
    """
    if not is_public_cidr(str(ingress_rule.get(source_field, ""))):
        return None

    policy = str(ingress_rule.get("policy", "accept")).casefold()
    protocol = str(ingress_rule.get("ip_protocol", "")).casefold()
    priority = _parse_priority(ingress_rule)
    port_range = ingress_rule.get("port_range", "")
    if policy not in ("accept", "drop") or protocol not in ("tcp", "all"):
        return None
    if priority is None or not isinstance(port_range, str):
        return None

    if protocol == "all" and port_range == ALL_PORTS_RANGE:
        return EffectiveRule(policy, priority, 1, MAX_PORT)
    if protocol == "tcp" and port_range == ALL_PORTS_RANGE:
        return None

    try:
        range_parts = port_range.split("/")
        if len(range_parts) == 1:
            from_port = to_port = int(range_parts[0])
        elif len(range_parts) == 2:
            from_port, to_port = map(int, range_parts)
        else:
            return None
    except ValueError:
        return None

    if not (MIN_PORT <= from_port <= to_port <= MAX_PORT):
        return None
    if to_port < 1:
        return None
    return EffectiveRule(policy, priority, max(1, from_port), to_port)


def _effective_policy(rules: Sequence[EffectiveRule], port: int) -> str | None:
    """Resolve the effective policy for a port using Alibaba priorities.

    Lower priority numbers win, and Drop wins when policies share the same
    winning priority.

    Args:
        rules: Normalized rules for one public address family.
        port: Port whose effective policy is requested.

    Returns:
        "accept", "drop", or None when no rule matches.
    """
    matching_rules = [rule for rule in rules if rule.from_port <= port <= rule.to_port]
    if not matching_rules:
        return None
    winning_priority = min(rule.priority for rule in matching_rules)
    winning_policies = {
        rule.policy for rule in matching_rules if rule.priority == winning_priority
    }
    return "drop" if "drop" in winning_policies else "accept"


def get_publicly_exposed_tcp_ports(
    ingress_rules: Collection[Mapping[str, object]], target_ports: Collection[int]
) -> set[int]:
    """Return target TCP ports effectively accepted from either public address family.

    Priority is resolved only among rules in this audited security group. Combining
    effective reachability across multiple security groups attached to a resource is
    outside the scope of a security-group resource check.
    """
    exposed_ports: set[int] = set()
    valid_target_ports = {
        port
        for port in target_ports
        if isinstance(port, int)
        and not isinstance(port, bool)
        and 1 <= port <= MAX_PORT
    }
    for source_field in PUBLIC_SOURCE_FIELDS:
        effective_rules = [
            parsed_rule
            for ingress_rule in ingress_rules
            if (parsed_rule := _parse_effective_rule(ingress_rule, source_field))
            is not None
        ]
        for port in valid_target_ports:
            if _effective_policy(effective_rules, port) == "accept":
                exposed_ports.add(port)
    return exposed_ports


def is_public_ingress_exposing_all_ports(
    ingress_rules: Collection[Mapping[str, object]],
) -> bool:
    """Return whether either public address family has effective all-protocol coverage."""
    for source_field in PUBLIC_SOURCE_FIELDS:
        all_protocol_rules = [
            parsed_rule
            for ingress_rule in ingress_rules
            if str(ingress_rule.get("ip_protocol", "")).casefold() == "all"
            if (parsed_rule := _parse_effective_rule(ingress_rule, source_field))
            is not None
        ]
        tcp_rules = [
            parsed_rule
            for ingress_rule in ingress_rules
            if str(ingress_rule.get("ip_protocol", "")).casefold() == "tcp"
            if (parsed_rule := _parse_effective_rule(ingress_rule, source_field))
            is not None
        ]
        boundaries = {1, MAX_PORT + 1}
        for rule in (*all_protocol_rules, *tcp_rules):
            boundaries.add(rule.from_port)
            boundaries.add(rule.to_port + 1)
        ordered_boundaries = sorted(boundaries)
        if all(
            _effective_policy(all_protocol_rules, ordered_boundaries[index]) == "accept"
            and _effective_policy(
                [*all_protocol_rules, *tcp_rules], ordered_boundaries[index]
            )
            == "accept"
            for index in range(len(ordered_boundaries) - 1)
        ):
            return True
    return False


def format_ports(ports: Collection[int]) -> str:
    """Return stable, human-readable port evidence."""
    ordered_ports = list(ports) if isinstance(ports, Sequence) else sorted(ports)
    if len(ordered_ports) == 1:
        return str(ordered_ports[0])
    if len(ordered_ports) == 2:
        return f"{ordered_ports[0]} and {ordered_ports[1]}"
    return f"{', '.join(map(str, ordered_ports[:-1]))}, and {ordered_ports[-1]}"
