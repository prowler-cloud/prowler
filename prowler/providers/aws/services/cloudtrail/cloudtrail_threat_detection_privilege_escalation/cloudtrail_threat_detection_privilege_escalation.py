import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_threat_detection_privilege_escalation(Check):
    def execute(self):
        findings = []
        threshold = cloudtrail_client.audit_config.get(
            "threat_detection_privilege_escalation_threshold", 0.1
        )
        threat_detection_minutes = cloudtrail_client.audit_config.get(
            "threat_detection_privilege_escalation_minutes", 1440
        )
        privilege_escalation_actions = cloudtrail_client.audit_config.get(
            "threat_detection_privilege_escalation_actions", []
        )

        potential_privilege_escalation = {}
        found_potential_privilege_escalation = False
        multiregion_trail = None
        # Check if any trail is multi-region so we only need to check once
        for trail in cloudtrail_client.trails.values():
            if trail.is_multiregion:
                multiregion_trail = trail
                break
        trails_to_scan = (
            cloudtrail_client.trails.values()
            if not multiregion_trail
            else [multiregion_trail]
        )
        for trail in trails_to_scan:
            for event_name in privilege_escalation_actions:
                for event_log in cloudtrail_client.__lookup_events__(
                    trail=trail,
                    event_name=event_name,
                    minutes=threat_detection_minutes,
                ):
                    event_log = json.loads(event_log["CloudTrailEvent"])
                    if ".amazonaws.com" not in event_log["sourceIPAddress"]:
                        if (
                            event_log["sourceIPAddress"]
                            not in potential_privilege_escalation
                        ):
                            potential_privilege_escalation[
                                event_log["sourceIPAddress"]
                            ] = set()
                        potential_privilege_escalation[
                            event_log["sourceIPAddress"]
                        ].add(event_name)
        for source_ip, actions in potential_privilege_escalation.items():
            ip_threshold = round(len(actions) / len(privilege_escalation_actions), 2)
            if len(actions) / len(privilege_escalation_actions) > threshold:
                found_potential_privilege_escalation = True
                report = Check_Report_AWS(self.metadata())
                report.region = cloudtrail_client.region
                report.resource_id = cloudtrail_client.audited_account
                report.resource_arn = cloudtrail_client.__get_trail_arn_template__(
                    cloudtrail_client.region
                )
                report.status = "FAIL"
                report.status_extended = f"Potential privilege escalation attack detected from source IP {source_ip} with an threshold of {ip_threshold}."
                findings.append(report)
        if not found_potential_privilege_escalation:
            report = Check_Report_AWS(self.metadata())
            report.region = cloudtrail_client.region
            report.resource_id = cloudtrail_client.audited_account
            report.resource_arn = cloudtrail_client.__get_trail_arn_template__(
                cloudtrail_client.region
            )
            report.status = "PASS"
            report.status_extended = (
                "No potential privilege escalation attack detected."
            )
            findings.append(report)
        return findings
