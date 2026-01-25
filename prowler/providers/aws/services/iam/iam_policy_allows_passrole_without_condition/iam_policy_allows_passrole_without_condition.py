from prowler.lib.check.models import Check, Check_Report
from prowler.providers.aws.services.iam.iam_client import iam_client

class iam_policy_allows_passrole_without_condition(Check):
    def execute(self):
        findings = []
        for policy in iam_client.policies.values():
            if policy.type == "Custom":
                report = Check_Report(self.metadata(), policy)
                report.status = "PASS"
                report.status_extended = f"Policy {policy.name} does not allow unrestricted PassRole."
                report.resource_id = policy.name
                report.resource_arn = policy.arn

                if policy.document:
                    statements = policy.document.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for statement in statements:
                        if statement.get("Effect") == "Allow":
                            actions = statement.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if "iam:PassRole" in actions or "*" in actions:
                                resources = statement.get("Resource", [])
                                if isinstance(resources, str):
                                    resources = [resources]
                                
                                if "*" in resources:
                                    # Robust check for Condition or condition
                                    has_condition = "Condition" in statement or "condition" in statement
                                    
                                    if not has_condition:
                                        report.status = "FAIL"
                                        report.status_extended = f"Policy {policy.name} allows iam:PassRole on * without conditions."
                                        break 

                findings.append(report)
        return findings
