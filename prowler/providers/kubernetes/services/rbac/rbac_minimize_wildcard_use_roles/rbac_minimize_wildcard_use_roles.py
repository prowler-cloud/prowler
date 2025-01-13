from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.rbac.rbac_client import rbac_client


class rbac_minimize_wildcard_use_roles(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        # Check ClusterRoles for wildcards
        for cr in rbac_client.cluster_roles.values():
            report = Check_Report_Kubernetes(self.metadata(), cr.metadata)
            report.status = "PASS"
            report.status_extended = (
                f"ClusterRole {cr.metadata.name} does not use wildcards."
            )

            for rule in cr.rules:
                if (rule.resources and "*" in str(rule.resources)) or (
                    rule.verbs and "*" in rule.verbs
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ClusterRole {cr.metadata.name} uses wildcards."
                    )
            findings.append(report)

        # Check Roles for wildcards
        for role in rbac_client.roles.values():
            report = Check_Report_Kubernetes(self.metadata(), role.metadata)
            report.status = "PASS"
            report.status_extended = (
                f"Role {role.metadata.name} does not use wildcards."
            )

            for rule in role.rules:
                if (rule.resources and "*" in str(rule.resources)) or (
                    rule.verbs and "*" in rule.verbs
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Role {role.metadata.name} uses wildcards."
                    )
            findings.append(report)

        return findings
