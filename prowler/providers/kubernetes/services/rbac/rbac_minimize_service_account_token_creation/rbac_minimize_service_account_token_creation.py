from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.rbac.rbac_client import rbac_client


class rbac_minimize_service_account_token_creation(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for crb in rbac_client.cluster_role_bindings:
            for subject in crb.subjects:
                if subject.kind in ["User", "Group"]:
                    service_account_access = False
                    report = Check_Report_Kubernetes(self.metadata())
                    report.namespace = "cluster-wide"
                    report.resource_name = subject.name
                    report.resource_id = subject.uid if hasattr(subject, "uid") else ""
                    report.status = "PASS"
                    report.status_extended = f"User or group '{subject.name}' does not have access to create service account tokens."
                    for cr in rbac_client.cluster_roles:
                        if service_account_access:
                            break
                        if cr.metadata.name == crb.roleRef.name:
                            if cr.rules:
                                for rule in cr.rules:
                                    if (
                                        rule.resources
                                        and ["serviceaccounts/token"] in rule.resources
                                        and rule.verbs
                                        and "create" in rule.verbs
                                    ):
                                        service_account_access = True
                                        report.status = "FAIL"
                                        report.status_extended = f"User or group '{subject.name}' has access to create service account tokens."
                                        break
                    findings.append(report)

        return findings
