"""
This module contains functions related to monitoring alerts in Azure.
"""


def check_alert_rule(alert_rule, expected_equal) -> bool:
    """
    Checks if an alert rule meets the specified condition.

    Args:
        alert_rule: An object representing the alert rule to be checked.
        expected_equal: The expected value for the "operationName" field.

    Returns:
        A boolean value indicating whether the alert rule meets the condition.
    """

    if alert_rule.enabled:
        for element in alert_rule.condition.all_of:
            if element.field == "operationName" and element.equals == expected_equal:
                return True

    return False
