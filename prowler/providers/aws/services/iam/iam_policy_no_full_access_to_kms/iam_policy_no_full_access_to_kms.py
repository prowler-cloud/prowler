from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import check_full_service_access

critical_service = "kms"


class iam_policy_no_full_access_to_kms(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for policy in iam_client.policies:
            # Check only custom policies
            if policy.type == "Custom":
                report = Check_Report_AWS(metadata=self.metadata(), resource=policy)
                report.region = iam_client.region
                report.status = "PASS"
                report.status_extended = f"Custom Policy {policy.name} does not allow '{critical_service}:*' privileges."
                if policy.document and check_full_service_access(
                    critical_service, policy.document
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Custom Policy {policy.name} allows '{critical_service}:*' privileges."

                findings.append(report)
        return findings
