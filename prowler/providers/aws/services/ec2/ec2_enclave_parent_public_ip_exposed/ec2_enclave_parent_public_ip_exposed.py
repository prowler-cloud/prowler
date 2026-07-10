from ipaddress import IPv6Address

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import is_enclave_parent
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_enclave_parent_public_ip_exposed(Check):
    """Ensure Nitro Enclave parent instances are not internet-reachable.

    Nitro Enclaves have no network interface of their own; all ingress and
    egress reach the enclave through the parent EC2 instance over vsock. A
    parent that is reachable from the public Internet — via a public IPv4, a
    globally-routable IPv6 on its ENI, or a subnet whose route table sends
    ``0.0.0.0/0`` or ``::/0`` to an Internet Gateway — is a direct attack
    surface against the only communication channel the enclave has.

    - PASS: The parent has no public IPv4/IPv6 and its subnet is not public.
    - FAIL: Any of those signals is present.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            has_public_ipv4 = bool(instance.public_ip)

            global_ipv6_addresses = []
            for eni_id in instance.network_interfaces or []:
                eni = ec2_client.network_interfaces.get(eni_id)
                if eni is None:
                    continue
                for address in eni.public_ip_addresses or []:
                    if isinstance(address, IPv6Address):
                        global_ipv6_addresses.append(str(address))

            subnet = vpc_client.vpc_subnets.get(instance.subnet_id)
            in_public_ipv4_subnet = bool(subnet and subnet.public)
            in_public_ipv6_subnet = bool(subnet and subnet.public_ipv6)

            if (
                not has_public_ipv4
                and not global_ipv6_addresses
                and not in_public_ipv4_subnet
                and not in_public_ipv6_subnet
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} has no public IP "
                    f"and is not in a public subnet."
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
                    reasons.append(
                        "its subnet routes 0.0.0.0/0 to an internet gateway"
                    )
                if in_public_ipv6_subnet:
                    reasons.append("its subnet routes ::/0 to an internet gateway")
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} is internet-exposed: "
                    + " and ".join(reasons)
                    + "."
                )
            findings.append(report)
        return findings
