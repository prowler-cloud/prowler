from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_security_context_deny_plugin(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            security_context_deny_set = False
            pod_security_policy_set = False
            for container in pod.containers.values():
                pod_security_policy_set = False
                security_context_deny_set = False
                for command in container.command:
                    if command.startswith("--enable-admission-plugins"):
                        if "SecurityContextDeny" in (command.split("=")[1]):
                            security_context_deny_set = True
                        if "PodSecurityPolicy" in (command.split("=")[1]):
                            pod_security_policy_set = True
                if not pod_security_policy_set or not security_context_deny_set:
                    break

            if pod_security_policy_set:
                report.status = "PASS"
                report.status_extended = (
                    f"PodSecurityPolicy is in use in pod {pod.name}."
                )
            elif security_context_deny_set:
                report.status = "PASS"
                report.status_extended = f"SecurityContextDeny admission control plugin is set in pod {pod.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Neither SecurityContextDeny nor PodSecurityPolicy admission control plugins are set in pod {pod.name}."

            findings.append(report)
        return findings
