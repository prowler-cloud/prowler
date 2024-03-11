from prowler.lib.check.models import Check_Report_Azure


def check_alerts_review(
    activity_log_alerts, expected_equal, report_metadata, subscription_name
) -> Check_Report_Azure:
    report = Check_Report_Azure(report_metadata)
    report.status = "FAIL"
    report.subscription = subscription_name
    report.resource_name = "Monitor"
    report.resource_id = "Monitor"
    action = "delete"
    if expected_equal.split("/")[-1] == "write":
        action = "create"
    report.status_extended = f"There is not an alert for {action} {expected_equal.split('/')[-2]} in subscription {subscription_name}."
    for alert_rule in activity_log_alerts:
        if (
            alert_rule.condition.all_of[1].equals == expected_equal
            and alert_rule.enabled
        ):
            report.status = "PASS"
            report.resource_name = alert_rule.name
            report.resource_id = alert_rule.id
            report.subscription = subscription_name
            report.status_extended = f"There is an alert configured for {action} {expected_equal.split('/')[-2]} in subscription {subscription_name}."

            break

    return report
