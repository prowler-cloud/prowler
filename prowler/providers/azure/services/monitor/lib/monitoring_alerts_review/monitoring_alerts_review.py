def check_alerts_review(alert_rule, expected_equal) -> bool:
    check = False

    if alert_rule.enabled:
        for element in alert_rule.condition.all_of:
            if element.field == "operationName" and element.equals == expected_equal:
                check = True

    return check
