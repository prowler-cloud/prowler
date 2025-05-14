from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.rbac.lib.role_permissions import (
    is_rule_allowing_permissions,
)
from prowler.providers.kubernetes.services.rbac.rbac_client import rbac_client

verbs = ["get", "list", "watch"]
resources = ["secret"]


class rbac_minimize_secret_access(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        # Check ClusterRoleBindings for seceret access
        for cr in rbac_client.cluster_roles.values():
            report = Check_Report_Kubernetes(
                metadata=self.metadata(), resource=cr.metadata
            )
            report.status = "PASS"
            report.status_extended = (
                f"ClusterRole {cr.metadata.name} does not have secret access."
            )
            if is_rule_allowing_permissions(cr.rules, resources, verbs):
                report.status = "FAIL"
                report.status_extended = (
                    f"ClusterRole {cr.metadata.name} has secret access."
                )
            findings.append(report)

        # Check RoleBindings for secret access
        for role in rbac_client.roles.values():
            report = Check_Report_Kubernetes(
                metadata=self.metadata(), resource=role.metadata
            )
            report.status = "PASS"
            report.status_extended = (
                f"Role {role.metadata.name} does not have secret access."
            )

            if is_rule_allowing_permissions(cr.rules, resources, verbs):
                report.status = "FAIL"
                report.status_extended = f"Role {role.metadata.name} has secret access."
            findings.append(report)

        return findings
