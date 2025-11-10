from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)


class cloudstorage_bucket_lifecycle_management_enabled(Check):
    """Ensure Cloud Storage buckets have lifecycle management enabled with at least one valid rule.

    Reports PASS if a bucket has at least one valid lifecycle rule
    (with a supported action and condition), otherwise FAIL.

    """

    def execute(self) -> list[Check_Report_GCP]:
        """Run the lifecycle management check for each Cloud Storage bucket.

        Returns:
            list[Check_Report_GCP]: Results for all evaluated buckets.
        """

        findings = []
        for bucket in cloudstorage_client.buckets:
            report = Check_Report_GCP(metadata=self.metadata(), resource=bucket)
            report.status = "FAIL"
            report.status_extended = (
                f"Bucket {bucket.name} does not have lifecycle management enabled."
            )

            rules = bucket.lifecycle_rules

            if rules:
                valid_rules = []
                for rule in rules:
                    action_type = rule.get("action", {}).get("type")
                    condition = rule.get("condition")
                    if action_type and condition:
                        valid_rules.append(rule)

                if valid_rules:
                    report.status = "PASS"
                    report.status_extended = f"Bucket {bucket.name} has lifecycle management enabled with {len(valid_rules)} valid rule(s)."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Bucket {bucket.name} has lifecycle rules configured but none are valid."

            findings.append(report)
        return findings
