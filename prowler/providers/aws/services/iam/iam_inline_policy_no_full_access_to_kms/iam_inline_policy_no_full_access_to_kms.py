from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import check_full_service_access

critical_service = "kms"


class iam_inline_policy_no_full_access_to_kms(Check):
    def execute(self):
        findings = []

        for policy in iam_client.policies:
            if policy.type == "Inline":
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_arn = policy.arn
                report.resource_id = f"{policy.entity}/{policy.name}"
                report.resource_tags = policy.tags
                report.status = "PASS"

                resource_type_str = report.resource_arn.split(":")[-1].split("/")[0]
                resource_attached = report.resource_arn.split("/")[-1]

                report.status_extended = f"{policy.type} policy {policy.name}{' attached to ' + resource_type_str + ' ' + resource_attached if policy.attached else ''} does not allow '{critical_service}:*' privileges."

                if policy.document and check_full_service_access(
                    critical_service, policy.document
                ):
                    report.status = "FAIL"
                    report.status_extended = f"{policy.type} policy {policy.name}{' attached to ' + resource_type_str + ' ' + resource_attached if policy.attached else ''} allows '{critical_service}:*' privileges."

                findings.append(report)

        return findings
