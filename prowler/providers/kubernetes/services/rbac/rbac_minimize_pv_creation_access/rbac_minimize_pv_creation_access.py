from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.rbac.lib.role_permissions import (
    is_rule_allowing_permissions,
)
from prowler.providers.kubernetes.services.rbac.rbac_client import rbac_client

verbs = ["create"]
resources = ["persistentvolumes"]


class rbac_minimize_pv_creation_access(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        # Collect unique subjects and the ClusterRole names bound to them
        subjects_bound_roles = {}
        for crb in rbac_client.cluster_role_bindings.values():
            for subject in crb.subjects:
                # CIS benchmarks scope these checks to human identities only
                if subject.kind in ["User", "Group"]:
                    key = (subject.kind, subject.name, subject.namespace)
                    if key not in subjects_bound_roles:
                        subjects_bound_roles[key] = (subject, set())
                    subjects_bound_roles[key][1].add(crb.roleRef.name)

        for _, (subject, role_names) in subjects_bound_roles.items():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=subject)
            report.resource_name = f"{subject.kind}:{subject.name}"
            report.resource_id = f"{subject.kind}/{subject.name}"
            report.status = "PASS"
            report.status_extended = f"User or group '{subject.name}' does not have access to create PersistentVolumes."
            for cr in rbac_client.cluster_roles.values():
                if cr.metadata.name in role_names:
                    if is_rule_allowing_permissions(cr.rules, resources, verbs):
                        report.status = "FAIL"
                        report.status_extended = f"User or group '{subject.name}' has access to create PersistentVolumes."
                        break
            findings.append(report)

        return findings
