from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    check_admin_access,
    check_full_service_access,
)
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)


class bedrock_api_key_no_administrative_privileges(Check):
    def execute(self):
        findings = []
        for api_key in iam_client.service_specific_credentials:
            if api_key.service_name != "bedrock.amazonaws.com":
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=api_key)
            report.status = "PASS"
            report.status_extended = f"API key {api_key.id} in user {api_key.user.name} has no administrative privileges."
            for policy in api_key.user.attached_policies:
                policy_arn = policy["PolicyArn"]
                if policy_arn in iam_client.policies:
                    policy_document = iam_client.policies[policy_arn].document
                    if policy_document:
                        if check_admin_access(policy_document):
                            report.status = "FAIL"
                            report.status_extended = f"API key {api_key.id} in user {api_key.user.name} has administrative privileges through attached policy {policy['PolicyName']}."
                            break
                        elif check_privilege_escalation(policy_document):
                            report.status = "FAIL"
                            report.status_extended = f"API key {api_key.id} in user {api_key.user.name} has privilege escalation through attached policy {policy['PolicyName']}."
                            break
                        elif check_full_service_access("bedrock", policy_document):
                            report.status = "FAIL"
                            report.status_extended = f"API key {api_key.id} in user {api_key.user.name} has full service access through attached policy {policy['PolicyName']}."
                            break
            for inline_policy_name in api_key.user.inline_policies:
                inline_policy_arn = f"{api_key.user.arn}:policy/{inline_policy_name}"
                if inline_policy_arn in iam_client.policies:
                    policy_document = iam_client.policies[inline_policy_arn].document
                    if policy_document:
                        if check_admin_access(policy_document):
                            report.status = "FAIL"
                            report.status_extended = f"API key {api_key.id} in user {api_key.user.name} has administrative privileges through inline policy {inline_policy_name}."
                            break
                        elif check_privilege_escalation(policy_document):
                            report.status = "FAIL"
                            report.status_extended = f"API key {api_key.id} in user {api_key.user.name} has privilege escalation through inline policy {inline_policy_name}."
                            break
                        elif check_full_service_access("bedrock", policy_document):
                            report.status = "FAIL"
                            report.status_extended = f"API key {api_key.id} in user {api_key.user.name} has full service access through inline policy {inline_policy_name}."
                            break
            findings.append(report)

        return findings
