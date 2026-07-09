from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_hostpath_volume_mounts(Check):
    """Check if Pods mount hostPath volumes.

    hostPath volumes expose the node filesystem inside the pod, enabling
    container escape, tampering with host files and privilege escalation
    to the node, so their use should be minimized.
    """

    def execute(self) -> list[Check_Report_Kubernetes]:
        """Execute the check for every Pod collected by the core client.

        Returns:
            A list of reports, one per Pod: PASS when the Pod defines no
            hostPath volumes, FAIL when any volume is of type hostPath.
        """
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            host_path_volumes = [
                volume["name"]
                for volume in pod.volumes or []
                if volume.get("host_path")
            ]
            if host_path_volumes:
                report.status = "FAIL"
                report.status_extended = f"Pod {pod.name} mounts hostPath volumes: {', '.join(host_path_volumes)}."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Pod {pod.name} does not mount hostPath volumes."
                )
            findings.append(report)

        return findings
