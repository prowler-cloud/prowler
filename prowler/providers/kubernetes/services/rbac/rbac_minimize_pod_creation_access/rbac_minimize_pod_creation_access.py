from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.rbac.lib.role_permissions import (
    is_rule_allowing_permissions,
)
from prowler.providers.kubernetes.services.rbac.rbac_client import rbac_client

verbs = ["create"]
resources = ["pods"]


class rbac_minimize_pod_creation_access(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        # Check ClusterRoleBindings for pod create access
        for cr in rbac_client.cluster_roles.values():
            report = Check_Report_Kubernetes(
                metadata=self.metadata(), resource=cr.metadata
            )
            report.status = "PASS"
            report.status_extended = (
                f"ClusterRole {cr.metadata.name} does not have pod create access."
            )
            if is_rule_allowing_permissions(cr.rules, resources, verbs):
                report.status = "FAIL"
                report.status_extended = (
                    f"ClusterRole {cr.metadata.name} has pod create access."
                )
            findings.append(report)

        # Check RoleBindings for pod create access
        for role in rbac_client.roles.values():
            report = Check_Report_Kubernetes(
                metadata=self.metadata(), resource=role.metadata
            )
            report.status = "PASS"
            report.status_extended = (
                f"Role {role.metadata.name} does not have pod create access."
            )

            if is_rule_allowing_permissions(role.rules, resources, verbs):
                report.status = "FAIL"
                report.status_extended = (
                    f"Role {role.metadata.name} has pod create access."
                )
            findings.append(report)

        return findings
