import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)

THRESHOLD = cloudtrail_client.audit_config.get(
    "threat_detection_enumeration_threshold", 0.7
)
THREAT_DETECTION_MINUTES = cloudtrail_client.audit_config.get(
    "threat_detection_enumeration_minutes", 1440
)
ENUMERATION_ACTIONS = cloudtrail_client.audit_config.get(
    "threat_detection_enumeration_actions", []
)


class cloudtrail_threat_detection_enumeration(Check):
    def execute(self):
        findings = []
        potential_enumeration = {}
        found_potential_enumeration = False
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
            for event_name in ENUMERATION_ACTIONS:
                for event_log in cloudtrail_client.__lookup_events__(
                    trail=trail,
                    event_name=event_name,
                    minutes=THREAT_DETECTION_MINUTES,
                ):
                    event_log = json.loads(event_log["CloudTrailEvent"])
                    if ".amazonaws.com" not in event_log["sourceIPAddress"]:
                        if event_log["sourceIPAddress"] not in potential_enumeration:
                            potential_enumeration[event_log["sourceIPAddress"]] = set()
                        potential_enumeration[event_log["sourceIPAddress"]].add(
                            event_name
                        )
        for source_ip, actions in potential_enumeration.items():
            print(len(actions) / len(ENUMERATION_ACTIONS))
            if len(actions) / len(ENUMERATION_ACTIONS) > THRESHOLD:
                found_potential_enumeration = True
                report = Check_Report_AWS(self.metadata())
                report.region = trail.region
                report.resource_id = trail.name
                report.resource_arn = trail.arn
                report.resource_tags = trail.tags
                report.status = "FAIL"
                report.status_extended = f"Potential enumeration attack detected from source IP {source_ip} with an threshold of {THRESHOLD}."
                findings.append(report)
        if not found_potential_enumeration:
            report = Check_Report_AWS(self.metadata())
            report.region = trail.region
            report.resource_id = trail.name
            report.resource_arn = trail.arn
            report.resource_tags = trail.tags
            report.status = "PASS"
            report.status_extended = "No potential enumeration attack detected."
            findings.append(report)
        return findings
