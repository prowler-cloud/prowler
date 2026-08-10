from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import (
    HOST_TRUST_MODEL_BOILERPLATE,
    is_enclave_parent,
    rule_world_facing_port_range,
)


class ec2_confidential_workload_host_vsock_proxy_exposed(Check):
    """Ensure confidential-workload hosts do not expose likely vsock-proxy TCP ports.

    vsock itself is ``AF_VSOCK`` and is not reachable over TCP/IP, but common
    vsock-proxy applications (for example the Nitro Enclaves SDK proxy)
    bridge between vsock and TCP by listening on ports on the host. If those
    TCP ports are exposed to the internet, an attacker can interact with the
    proxy and potentially reach the enclave communication channel. The port
    set is configurable via ``enclave_vsock_ports`` and defaults to
    ``[5000, 8000-8090, 9000]``. This is a heuristic control. This check
    assesses the host environment; it does not audit the enclave itself.

    - PASS: No security-group rule opens a heuristic vsock-proxy port to the world.
    - FAIL: At least one such port is exposed to ``0.0.0.0/0`` or ``::/0``.
    - MANUAL: SGs referenced by the instance are not observable in the service
      cache; no exposure on the visible SGs but coverage is incomplete
      (fail-closed).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the confidential-workload host vsock-proxy exposure check.

        For every confidential-workload host, iterates the ingress rules of
        every attached security group and flags heuristic vsock-proxy TCP
        ports that allow ``0.0.0.0/0`` or ``::/0``.

        Returns:
            list[Check_Report_AWS]: One report per confidential-workload host.
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

            observed_sg_ids = {sg.id for sg in ec2_client.security_groups.values()}
            missing_sgs = [
                sg_id
                for sg_id in (instance.security_groups or [])
                if sg_id not in observed_sg_ids
            ]

            for sg in ec2_client.security_groups.values():
                if sg.id not in instance.security_groups:
                    continue
                for rule in sg.ingress_rules:
                    port_range = rule_world_facing_port_range(rule)
                    if port_range is None:
                        continue
                    if port_range == "all":
                        exposed_ports.update(vsock_ports)
                        continue
                    from_port, to_port = port_range
                    exposed_ports.update(
                        vsock_ports.intersection(range(from_port, to_port + 1))
                    )

            if exposed_ports:
                report.status = "FAIL"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} exposes "
                    f"likely vsock-proxy TCP ports {sorted(exposed_ports)} "
                    f"to the internet. This check is heuristic and may "
                    f"false-positive on non-vsock services on the same "
                    f"ports. {HOST_TRUST_MODEL_BOILERPLATE}"
                )
            elif missing_sgs:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} vsock-proxy "
                    f"exposure cannot be fully verified: security group(s) "
                    + ", ".join(missing_sgs)
                    + f" not observable. No heuristic vsock-proxy port "
                    f"exposed on the visible SGs. "
                    f"{HOST_TRUST_MODEL_BOILERPLATE}"
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} does not "
                    f"expose any heuristic vsock-proxy TCP ports to the "
                    f"internet. {HOST_TRUST_MODEL_BOILERPLATE}"
                )
            findings.append(report)
        return findings
