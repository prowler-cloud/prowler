from ipaddress import IPv6Address

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import (
    HOST_TRUST_MODEL_BOILERPLATE,
    is_enclave_parent,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_confidential_workload_host_public_ip(Check):
    """Ensure confidential-workload hosts are not internet-reachable.

    A confidential-workload host (an EC2 instance with
    ``EnclaveOptions.Enabled=true``) that is reachable from the public
    Internet — via a public IPv4, a globally-routable IPv6 on its ENI, or a
    subnet whose route table sends ``0.0.0.0/0`` or ``::/0`` to an Internet
    Gateway — expands the host attack surface unnecessarily. This check
    assesses the host environment; it does not audit the enclave itself.

    - PASS: The host has no public IPv4/IPv6 and its subnet is not public.
    - FAIL: Any of those signals is present.
    - MANUAL: ENI or subnet referenced by the instance is not observable in
      the service cache; the visible surface shows no exposure but coverage
      is incomplete (fail-closed).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the confidential-workload host public-IP exposure check.

        For each confidential-workload host, checks the instance's public IPv4,
        every attached ENI for a globally-routable IPv6 address, and its
        subnet's route table for a default route to an Internet Gateway
        (IPv4 ``0.0.0.0/0`` or IPv6 ``::/0``). NAT-gateway routes are not
        flagged. When ENI or subnet resolution fails from the service cache,
        the check emits MANUAL rather than PASS to avoid a false negative.

        Returns:
            list[Check_Report_AWS]: One report per confidential-workload host.
        """
        findings = []
        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            has_public_ipv4 = bool(instance.public_ip)

            # Track dependencies that could not be resolved. A missing ENI or
            # subnet means the exposure signal for that path is unobservable,
            # not "no exposure" — surface it as MANUAL to avoid a false PASS.
            missing_deps: list = []

            global_ipv6_addresses = []
            for eni_id in instance.network_interfaces or []:
                eni = ec2_client.network_interfaces.get(eni_id)
                if eni is None:
                    missing_deps.append(f"ENI {eni_id}")
                    continue
                for address in eni.public_ip_addresses or []:
                    if isinstance(address, IPv6Address):
                        global_ipv6_addresses.append(str(address))

            subnet = vpc_client.vpc_subnets.get(instance.subnet_id)
            if instance.subnet_id and subnet is None:
                missing_deps.append(f"subnet {instance.subnet_id}")
            in_public_ipv4_subnet = bool(subnet and subnet.public)
            in_public_ipv6_subnet = bool(subnet and subnet.public_ipv6)

            if (
                not has_public_ipv4
                and not global_ipv6_addresses
                and not in_public_ipv4_subnet
                and not in_public_ipv6_subnet
            ):
                if missing_deps:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Confidential-workload host {instance.id} exposure "
                        f"cannot be fully verified: dependency data not "
                        f"observable for "
                        + ", ".join(missing_deps)
                        + f". No public IP/subnet observed on the visible "
                        f"surface. {HOST_TRUST_MODEL_BOILERPLATE}"
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Confidential-workload host {instance.id} has no "
                        f"public IP and is not in a public subnet. "
                        f"{HOST_TRUST_MODEL_BOILERPLATE}"
                    )
            else:
                reasons = []
                if has_public_ipv4:
                    reasons.append(f"public IPv4 {instance.public_ip}")
                if global_ipv6_addresses:
                    reasons.append(
                        "global IPv6 address on its ENI ("
                        + ", ".join(global_ipv6_addresses)
                        + ")"
                    )
                if in_public_ipv4_subnet:
                    reasons.append("its subnet routes 0.0.0.0/0 to an internet gateway")
                if in_public_ipv6_subnet:
                    reasons.append("its subnet routes ::/0 to an internet gateway")
                report.status = "FAIL"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} is "
                    f"internet-exposed: "
                    + " and ".join(reasons)
                    + f". {HOST_TRUST_MODEL_BOILERPLATE}"
                )
            findings.append(report)
        return findings
