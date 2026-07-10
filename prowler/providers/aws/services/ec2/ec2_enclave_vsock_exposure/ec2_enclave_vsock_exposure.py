from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import (
    is_enclave_parent,
    rule_world_facing_port_range,
)


class ec2_enclave_vsock_exposure(Check):
    """Ensure Nitro Enclave parents do not expose likely vsock-proxy TCP ports.

    vsock itself is ``AF_VSOCK`` and is not reachable over TCP/IP, but common
    vsock-proxy applications (for example the Nitro Enclaves SDK proxy) bridge
    between vsock and TCP by listening on ports on the parent. If those TCP
    ports are exposed to the internet, an attacker can interact with the proxy
    and potentially reach the enclave communication channel.

    The port set is configurable via ``enclave_vsock_ports`` and defaults to
    ``[5000, 8000-8090, 9000]``. This is a heuristic control: it cannot detect
    proxies on non-standard ports and may false-positive on other services.

    - PASS: No security-group rule opens a heuristic vsock-proxy port to the world.
    - FAIL: At least one such port is exposed to ``0.0.0.0/0`` or ``::/0``.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Nitro Enclave vsock-proxy exposure check.

        For every enclave-parent instance, iterates the ingress rules of every
        attached security group and flags heuristic vsock-proxy TCP ports that
        allow ``0.0.0.0/0`` or ``::/0``.

        Returns:
            list[Check_Report_AWS]: One report per enclave-enabled instance.
        """
        findings = []
        vsock_ports = set(
            ec2_client.audit_config.get(
                "enclave_vsock_ports",
                [5000, *range(8000, 8091), 9000],
            )
        )

        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            exposed_ports = set()

            for sg in ec2_client.security_groups.values():
                if sg.id not in instance.security_groups:
                    continue
                for rule in sg.ingress_rules:
                    port_range = rule_world_facing_port_range(rule)
                    if port_range is None:
                        continue
                    if port_range == "all":
                        # Rule opens every port → every watched vsock port
                        # is exposed too.
                        exposed_ports.update(vsock_ports)
                        continue
                    from_port, to_port = port_range
                    exposed_ports.update(
                        vsock_ports.intersection(range(from_port, to_port + 1))
                    )

            if exposed_ports:
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} exposes likely "
                    f"vsock-proxy TCP ports {sorted(exposed_ports)} to the internet. "
                    f"This check is heuristic: vsock is AF_VSOCK (not TCP), but "
                    f"vsock-proxy applications often bridge to TCP on these ports; "
                    f"non-vsock services on the same ports may false-positive."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} does not expose any "
                    f"heuristic vsock-proxy TCP ports to the internet."
                )
            findings.append(report)
        return findings
