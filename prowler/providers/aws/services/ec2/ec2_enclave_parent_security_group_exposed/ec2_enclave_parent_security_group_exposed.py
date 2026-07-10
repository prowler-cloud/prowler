from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import (
    is_enclave_parent,
    rule_world_facing_port_range,
)


class ec2_enclave_parent_security_group_exposed(Check):
    """Ensure Nitro Enclave parent instances do not expose non-standard ports.

    Security groups attached to the parent are evaluated for ingress rules that
    permit ``0.0.0.0/0`` or ``::/0`` on TCP/UDP ports outside a configurable
    allow-list (``enclave_sg_allow_ports``; defaults to ``[22, 80, 443]``).
    Because vsock-proxy applications often listen on high ports, unrestricted
    ingress on those ports can expose the enclave's only communication channel.

    - PASS: No security-group rule exposes a non-allow-listed port to the world.
    - FAIL: At least one rule opens a non-allow-listed port to the world.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Nitro Enclave parent security-group exposure check.

        For each enclave-parent instance, iterates over every ingress rule of
        every attached security group and flags rules that allow world ingress
        on TCP ports outside the configured allow-list. Rules with no port
        bounds (e.g., ``IpProtocol=-1``) are flagged as an ``all`` exposure.

        Returns:
            list[Check_Report_AWS]: One report per enclave-enabled instance.
        """
        findings = []
        allow_ports = set(
            ec2_client.audit_config.get("enclave_sg_allow_ports", [22, 80, 443])
        )
        # Above this many non-allow-listed ports in a single rule, summarize
        # them as "from-to" in the finding message instead of listing every
        # individual port (would produce huge unreadable messages).
        summary_threshold = 10

        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            exposed_ports = set()

            for sg in ec2_client.security_groups.values():
                if sg.id not in instance.security_groups:
                    continue
                for rule in sg.ingress_rules:
                    port_range = rule_world_facing_port_range(
                        rule, protocols=("tcp", "udp")
                    )
                    if port_range is None:
                        continue
                    if port_range == "all":
                        exposed_ports.add("all")
                        continue
                    from_port, to_port = port_range
                    non_allowed = set(range(from_port, to_port + 1)) - allow_ports
                    if not non_allowed:
                        continue
                    if len(non_allowed) > summary_threshold:
                        exposed_ports.add(f"{from_port}-{to_port}")
                    else:
                        exposed_ports.update(non_allowed)

            if exposed_ports:
                numeric_ports = sorted(p for p in exposed_ports if isinstance(p, int))
                labels = sorted(p for p in exposed_ports if isinstance(p, str))
                ports_str = ", ".join(str(p) for p in numeric_ports + labels)
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} has security groups "
                    f"that expose non-allow-listed ports to the internet: "
                    f"{ports_str}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} exposes only "
                    f"allow-listed ports {sorted(allow_ports)} (if any) to the internet."
                )
            findings.append(report)
        return findings
