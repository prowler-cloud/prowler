import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_threat_detection_privilege_escalation(Check):
    def execute(self):
        findings = []
        threshold = cloudtrail_client.audit_config.get(
            "threat_detection_privilege_escalation_threshold", 0.2
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
                for event_log in cloudtrail_client._lookup_events(
                    trail=trail,
                    event_name=event_name,
                    minutes=threat_detection_minutes,
                ):
                    event_log = json.loads(event_log["CloudTrailEvent"])
                    if (
                        "arn" in event_log["userIdentity"]
                    ):  # Ignore event logs without ARN since they are AWS services
                        if (
                            event_log["userIdentity"]["arn"],
                            event_log["userIdentity"]["type"],
                        ) not in potential_privilege_escalation:
                            potential_privilege_escalation[
                                (
                                    event_log["userIdentity"]["arn"],
                                    event_log["userIdentity"]["type"],
                                )
                            ] = set()
                        potential_privilege_escalation[
                            (
                                event_log["userIdentity"]["arn"],
                                event_log["userIdentity"]["type"],
                            )
                        ].add(event_name)
        for aws_identity, actions in potential_privilege_escalation.items():
            identity_threshold = round(
                len(actions) / len(privilege_escalation_actions), 2
            )
            aws_identity_type = aws_identity[1]
            aws_identity_arn = aws_identity[0]
            if len(actions) / len(privilege_escalation_actions) > threshold:
                found_potential_privilege_escalation = True
                report = Check_Report_AWS(self.metadata())
                report.region = cloudtrail_client.region
                report.resource_id = cloudtrail_client.audited_account
                report.resource_arn = cloudtrail_client._get_trail_arn_template(
                    cloudtrail_client.region
                )
                report.status = "FAIL"
                report.status_extended = f"Potential privilege escalation attack detected from AWS {aws_identity_type} {aws_identity_arn.split('/')[-1]} with an threshold of {identity_threshold}."
                findings.append(report)
        if not found_potential_privilege_escalation:
            report = Check_Report_AWS(self.metadata())
            report.region = cloudtrail_client.region
            report.resource_id = cloudtrail_client.audited_account
            report.resource_arn = cloudtrail_client._get_trail_arn_template(
                cloudtrail_client.region
            )
            report.status = "PASS"
            report.status_extended = (
                "No potential privilege escalation attack detected."
            )
            findings.append(report)
        return findings
