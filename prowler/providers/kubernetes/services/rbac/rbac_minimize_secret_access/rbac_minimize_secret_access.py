from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.rbac.rbac_client import rbac_client


class rbac_minimize_secret_access(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        # Check ClusterRoleBindings for seceret access
        for cr in rbac_client.cluster_roles:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = "cluster-wide"
            report.resource_name = cr.metadata.name
            report.resource_id = cr.metadata.uid
            report.status = "PASS"
            report.status_extended = (
                f"ClusterRole {cr.metadata.name} does not have secret access."
            )

            for rule in cr.rules:
                if (rule.resources and "secret" in rule.resources) and (
                    any(verb in rule.verbs for verb in ["get", "list", "watch"])
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ClusterRole {cr.metadata.name} has secret access."
                    )
                    break
            findings.append(report)

        # Check RoleBindings for secret access
        for role in rbac_client.roles:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = role.metadata.namespace
            report.resource_name = role.metadata.name
            report.resource_id = role.metadata.uid
            report.status = "PASS"
            report.status_extended = (
                f"Role {role.metadata.name} does not have secret access."
            )

            for rule in role.rules:
                if "secrets" in getattr(rule, "resources", []) and any(
                    verb in getattr(rule, "verbs", [])
                    for verb in ["get", "list", "watch"]
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Role {role.metadata.name} has secret access."
                    )
                    break
            findings.append(report)

        return findings
