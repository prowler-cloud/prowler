from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_auth_mode_not_always_allow(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = f"API Server authorization mode is not set to AlwaysAllow in pod {pod.name}."
            # Scan every container for --authorization-config first: the
            # mode-based verdict below stops at the first container that
            # looks like AlwaysAllow, which would otherwise skip a later
            # API server container carrying this flag.
            authorization_config = any(
                command == "--authorization-config"
                or command.startswith("--authorization-config=")
                for container in pod.containers.values()
                for command in container.command or []
            )
            always_allow_in_auth_mode = True
            if not authorization_config:
                for container in pod.containers.values():
                    always_allow_in_auth_mode = True
                    commands = container.command or []
                    for index, command in enumerate(commands):
                        if command == "--authorization-mode":
                            # Space-separated form: the value is the next token.
                            value = (
                                commands[index + 1] if index + 1 < len(commands) else ""
                            )
                        elif command.startswith("--authorization-mode="):
                            value = command.partition("=")[2]
                        else:
                            continue
                        if "AlwaysAllow" not in value:
                            always_allow_in_auth_mode = False
                            break
                    if always_allow_in_auth_mode:
                        break
            if authorization_config:
                report.status = "PASS"
                report.status_extended = (
                    f"API Server authorization is configured through --authorization-config in pod {pod.name}; "
                    "the referenced configuration file was not inspected."
                )
            elif always_allow_in_auth_mode:
                report.status = "FAIL"
                report.status_extended = f"API Server authorization mode is set to AlwaysAllow in pod {pod.name}."
            findings.append(report)
        return findings
