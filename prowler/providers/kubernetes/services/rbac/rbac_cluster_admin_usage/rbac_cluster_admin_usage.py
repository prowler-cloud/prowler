from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.rbac.rbac_client import rbac_client


class rbac_cluster_admin_usage(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        # Iterate through the bindings
        for binding in rbac_client.cluster_role_bindings:
            # Check if the binding refers to the cluster-admin role
            if binding.roleRef.name == "cluster-admin":
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = (
                    "cluster-wide"
                    if not binding.metadata.namespace
                    else binding.metadata.namespace
                )
                report.resource_name = binding.metadata.name
                report.resource_id = binding.metadata.uid
                report.status = "MANUAL"
                report.status_extended = f"Cluster Role Binding {binding.metadata.name} uses cluster-admin role."
                findings.append(report)
        return findings
