import datetime

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.kms.kms_client import kms_client


class kms_key_rotation_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for key in kms_client.crypto_keys:
            report = Check_Report_GCP(self.metadata())
            report.project_id = key.project_id
            report.resource_id = key.id
            report.resource_name = key.name
            report.location = key.location
            now = datetime.datetime.now()
            condition_next_rotation_time = False
            if key.next_rotation_time:
                try:
                    next_rotation_time = datetime.datetime.strptime(
                        key.next_rotation_time, "%Y-%m-%dT%H:%M:%S.%fZ"
                    )
                except ValueError:
                    next_rotation_time = datetime.datetime.strptime(
                        key.next_rotation_time, "%Y-%m-%dT%H:%M:%SZ"
                    )
                condition_next_rotation_time = (
                    abs((next_rotation_time - now).days) <= 90
                )
            condition_rotation_period = False
            if key.rotation_period:
                condition_rotation_period = (
                    int(key.rotation_period[:-1]) // (24 * 3600) <= 90
                )
            if condition_rotation_period and condition_next_rotation_time:
                report.status = "PASS"
                report.status_extended = f"Key {key.name} is rotated every 90 days or less and the next rotation time is in less than 90 days."
            else:
                report.status = "FAIL"
                if condition_rotation_period:
                    report.status_extended = f"Key {key.name} is rotated every 90 days or less but the next rotation time is in more than 90 days."
                elif condition_next_rotation_time:
                    report.status_extended = f"Key {key.name} is not rotated every 90 days or less but the next rotation time is in less than 90 days."
                else:
                    report.status_extended = f"Key {key.name} is not rotated every 90 days or less and the next rotation time is in more than 90 days."
            findings.append(report)

        return findings
