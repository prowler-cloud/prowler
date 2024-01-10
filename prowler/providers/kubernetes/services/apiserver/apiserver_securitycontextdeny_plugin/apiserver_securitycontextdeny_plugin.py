from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_event_rate_limit(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = "SecurityContextDeny admission control plugin is set or PodSecurityPolicy is in use."
            security_context_deny_set = False
            pod_security_policy_set = False
            for container in pod.containers.values():
                if "--enable-admission-plugins" in container.command:
                    admission_plugins = container.command.split(
                        "--enable-admission-plugins="
                    )[1].split(",")
                    security_context_deny_set = (
                        "SecurityContextDeny" in admission_plugins
                    )
                    pod_security_policy_set = "PodSecurityPolicy" in admission_plugins

            if security_context_deny_set or pod_security_policy_set:
                report.status = "PASS"
            else:
                report.status = "FAIL"
                report.status_extended = "Neither SecurityContextDeny nor PodSecurityPolicy admission control plugins are set in container {container.name}."

            findings.append(report)
        return findings
