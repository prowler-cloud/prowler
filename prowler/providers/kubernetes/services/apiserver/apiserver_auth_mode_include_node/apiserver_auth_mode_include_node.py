from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_auth_mode_include_node(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = (
                f"API Server authorization mode includes Node in pod {pod.name}."
            )
            # Scan every container for --authorization-config first: it is
            # mutually exclusive with --authorization-mode, so a verdict
            # derived from the mode flags would be meaningless when the
            # config file form is used (e.g. Talos Linux).
            authorization_config = any(
                command == "--authorization-config"
                or command.startswith("--authorization-config=")
                for container in pod.containers.values()
                for command in container.command or []
            )
            node_auth_mode_set = False
            if not authorization_config:
                for container in pod.containers.values():
                    node_auth_mode_set = False
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
                        if "Node" in value:
                            node_auth_mode_set = True
                            break
                    if not node_auth_mode_set:
                        break
            if authorization_config:
                report.status = "PASS"
                report.status_extended = (
                    f"API Server authorization is configured through --authorization-config in pod {pod.name}; "
                    "the referenced configuration file was not inspected."
                )
            elif not node_auth_mode_set:
                report.status = "FAIL"
                report.status_extended = f"API Server authorization mode does not include Node in pod {pod.name}."
            findings.append(report)
        return findings
