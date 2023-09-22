from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_use_temporary_credentials(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for idx, last_accessed_services in enumerate(iam_client.last_accessed_services):
            report = Check_Report_AWS(self.metadata())
            report.resource_id = last_accessed_services["user"].name
            report.resource_arn = last_accessed_services["user"].arn
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = f"User {last_accessed_services['user'].name} doesn't have long lived credentials with access to other services than IAM or STS."
            if (
                len(
                    [
                        service
                        for service in last_accessed_services["services"]
                        if service["ServiceNamespace"] not in ["iam", "sts"]
                    ]
                )
                > 0
                and len(
                    [
                        akm
                        for akm in iam_client.access_keys_metadata[idx][
                            "access_keys_metadata"
                        ]
                        if len(akm["AccessKeyMetadata"]) > 0
                    ]
                )
                > 0
            ):
                report.status = "FAIL"
                report.status_extended = f"User {last_accessed_services['user'].name} have long lived credentials with access to other services than IAM or STS."

            findings.append(report)

        return findings
