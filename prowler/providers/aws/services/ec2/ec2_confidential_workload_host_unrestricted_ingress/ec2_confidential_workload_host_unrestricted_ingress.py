from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import (
    HOST_TRUST_MODEL_BOILERPLATE,
    UNRESTRICTED_INGRESS_SUMMARY_THRESHOLD,
    is_enclave_parent,
    rule_world_facing_port_range,
)


class ec2_confidential_workload_host_unrestricted_ingress(Check):
    """Ensure confidential-workload hosts do not expose non-standard ports.

    Security groups attached to the host are evaluated for ingress rules that
    permit ``0.0.0.0/0`` or ``::/0`` on TCP/UDP ports outside a configurable
    allow-list (``enclave_sg_allow_ports``; defaults to ``[22, 80, 443]``).
    This check assesses the host environment; it does not audit the enclave
    itself.

    - PASS: No security-group rule exposes a non-allow-listed port to the world.
    - FAIL: At least one rule opens a non-allow-listed port to the world.
    - MANUAL: SGs referenced by the instance are not observable in the service
      cache (e.g., collection failure) — no exposure verified on the visible
      SGs, but visibility is incomplete (fail-closed).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the confidential-workload host unrestricted-ingress check.

        For each confidential-workload host, iterates over every ingress rule
        of every attached security group and flags rules that allow world
        ingress on TCP/UDP ports outside the configured allow-list. Rules with
        no port bounds (e.g., ``IpProtocol=-1``) are flagged as ``all``.
        Non-allow-listed ranges larger than
        ``UNRESTRICTED_INGRESS_SUMMARY_THRESHOLD`` (10) are collapsed into a
        ``from-to`` label to keep the finding message actionable.

        Returns:
            list[Check_Report_AWS]: One report per confidential-workload host.
        """
        findings = []
        allow_ports = set(
            ec2_client.audit_config.get("enclave_sg_allow_ports", [22, 80, 443])
        )
        # Rebuilt once per scan; the SG dict does not change while iterating
        # instances.
        observed_sg_ids = {sg.id for sg in ec2_client.security_groups.values()}

        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            exposed_ports = set()

            # SGs referenced by the instance but not resolvable from the
            # service layer — treated as missing visibility (MANUAL) rather
            # than "no exposure". ec2_client.security_groups is indexed by
            # ARN, so match on the SG's .id attribute.
            missing_sgs = [
                sg_id
                for sg_id in (instance.security_groups or [])
                if sg_id not in observed_sg_ids
            ]

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
                    if len(non_allowed) > UNRESTRICTED_INGRESS_SUMMARY_THRESHOLD:
                        exposed_ports.add(f"{from_port}-{to_port}")
                    else:
                        exposed_ports.update(non_allowed)

            if exposed_ports:
                numeric_ports = sorted(p for p in exposed_ports if isinstance(p, int))
                labels = sorted(p for p in exposed_ports if isinstance(p, str))
                ports_str = ", ".join(str(p) for p in numeric_ports + labels)
                report.status = "FAIL"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} has security "
                    f"groups that expose non-allow-listed ports to the "
                    f"internet: {ports_str}. {HOST_TRUST_MODEL_BOILERPLATE}"
                )
            elif missing_sgs:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} ingress "
                    f"cannot be fully verified: security group(s) "
                    + ", ".join(missing_sgs)
                    + f" referenced by the instance were not observable. "
                    f"No non-allow-listed exposure found on the visible SGs. "
                    f"{HOST_TRUST_MODEL_BOILERPLATE}"
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} exposes only "
                    f"allow-listed ports {sorted(allow_ports)} (if any) to "
                    f"the internet. {HOST_TRUST_MODEL_BOILERPLATE}"
                )
            findings.append(report)
        return findings
