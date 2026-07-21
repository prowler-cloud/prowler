from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_hostpath_volume_mounts(Check):
    def execute(self) -> list[Check_Report_Kubernetes]:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = f"Pod {pod.name} does not use hostPath volumes."

            for volume in pod.volumes or []:
                if volume.get("host_path"):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Pod {pod.name} uses hostPath volume {volume['name']}."
                    )
                    break

            findings.append(report)

        return findings
