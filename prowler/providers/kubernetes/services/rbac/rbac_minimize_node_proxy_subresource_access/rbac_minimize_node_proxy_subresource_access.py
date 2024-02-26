from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.rbac.rbac_client import rbac_client


class rbac_minimize_node_proxy_subresource_access(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for crb in rbac_client.cluster_role_bindings:
            for subject in crb.subjects:
                if subject.kind in ["User", "Group"]:
                    access_node_proxy = False
                    report = Check_Report_Kubernetes(self.metadata())
                    report.namespace = "cluster-wide"
                    report.resource_name = subject.name
                    report.resource_id = subject.uid if hasattr(subject, "uid") else ""
                    report.status = "PASS"
                    report.status_extended = f"User or group '{subject.name}' does not have access to the node proxy sub-resource."
                    for cr in rbac_client.cluster_roles:
                        if access_node_proxy:
                            break
                        if cr.metadata.name == crb.roleRef.name:
                            if cr.rules:
                                for rule in cr.rules:
                                    if (
                                        rule.resources
                                        and "nodes/proxy" in rule.resources
                                        and rule.verbs
                                        and any(
                                            verb in rule.verbs
                                            for verb in ["get", "list", "watch"]
                                        )
                                    ):
                                        access_node_proxy = True
                                        report.status = "FAIL"
                                        report.status_extended = f"User or group '{subject.name}' has access to the node proxy sub-resource."
                                        break
                    findings.append(report)

        return findings
