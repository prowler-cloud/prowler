"""Helper functions for OCI Events service checks."""

import json
from typing import List, Optional

from prowler.lib.logger import logger


def check_event_rule_has_event_types(
    rule, required_event_types: List[str]
) -> tuple[bool, Optional[dict]]:
    """
    Check if an event rule contains all required event types in its condition.

    Args:
        rule: The OCI Event Rule object with condition attribute
        required_event_types: List of required event type strings (e.g., ['com.oraclecloud.cloudguard.problemdetected'])

    Returns:
        tuple: (has_all_types: bool, condition_dict: dict or None)
            - has_all_types: True if rule contains all required event types
            - condition_dict: Parsed condition dictionary, or None if parsing failed

    Example:
        >>> has_types, condition = check_event_rule_has_event_types(
        ...     rule,
        ...     ['com.oraclecloud.identitysignon.interactivelogin']
        ... )
        >>> if has_types:
        ...     print("Rule monitors user authentication")
    """
    try:
        # Parse the event condition JSON (handle single quotes)
        condition_str = rule.condition.lower().replace("'", '"')
        condition_dict = json.loads(condition_str)

        # Check if all required event types are in the condition
        if "eventtype" in condition_dict:
            event_types = condition_dict["eventtype"]
            if isinstance(event_types, list):
                # Check if all required event types are present
                has_all = all(evt in event_types for evt in required_event_types)
                return has_all, condition_dict

        return False, condition_dict

    except (json.JSONDecodeError, KeyError, AttributeError) as error:
        logger.debug(
            f"Failed to parse event rule condition for rule {getattr(rule, 'id', 'unknown')}: {error}"
        )
        return False, None


def check_event_rule_has_notification_actions(rule) -> bool:
    """
    Check if an event rule has notification actions configured.

    Args:
        rule: The OCI Event Rule object with actions attribute

    Returns:
        bool: True if rule has notification actions configured

    Example:
        >>> if check_event_rule_has_notification_actions(rule):
        ...     print("Rule has notifications configured")
    """
    try:
        return bool(rule.actions) and len(rule.actions) > 0
    except (AttributeError, TypeError):
        return False


def filter_rules_by_event_types(
    rules: List, required_event_types: List[str], check_active_only: bool = True
) -> List[tuple]:
    """
    Filter event rules by required event types.

    Args:
        rules: List of OCI Event Rule objects
        required_event_types: List of required event type strings
        check_active_only: If True, only check ACTIVE and enabled rules (default: True)

    Returns:
        List of tuples: [(rule, condition_dict), ...] for rules that match the criteria

    Example:
        >>> matching_rules = filter_rules_by_event_types(
        ...     events_client.rules,
        ...     ['com.oraclecloud.identitysignon.interactivelogin']
        ... )
        >>> for rule, condition in matching_rules:
        ...     print(f"Found matching rule: {rule.name}")
    """
    matching_rules = []

    for rule in rules:
        # Skip non-active or disabled rules if requested
        if check_active_only:
            if not (
                hasattr(rule, "lifecycle_state")
                and rule.lifecycle_state == "ACTIVE"
                and hasattr(rule, "is_enabled")
                and rule.is_enabled
            ):
                continue

        # Check if rule has required event types
        has_types, condition_dict = check_event_rule_has_event_types(
            rule, required_event_types
        )
        if has_types:
            matching_rules.append((rule, condition_dict))

    return matching_rules
