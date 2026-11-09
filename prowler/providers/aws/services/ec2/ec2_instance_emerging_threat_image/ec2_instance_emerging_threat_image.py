from typing import Optional

from prowler.lib.check.models import Check, Check_Report_AWS, Severity
from prowler.lib.threats import (
    describe_matches,
    load_signatures,
    match_image,
    to_match,
    worst_severity,
)
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_instance_emerging_threat_image(Check):
    """EC2 instances do not run an image that a known emerging threat affects.

    Threats are threat signatures (``prowler/lib/threats``): the built-in ones
    plus any the scan configuration supplies under ``threat_signatures``. The
    matched threats travel in the finding's raw payload so Prowler Cloud can
    turn them into Exploitability issues without reading prose.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        signatures = load_signatures(ec2_client.audit_config)
        if not signatures:
            return findings

        for instance in ec2_client.instances:
            if instance.state == "terminated":
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            if instance.image_id in ec2_client.image_lookup_failures:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Cannot evaluate EC2 Instance {instance.id} against known emerging "
                    f"threats: the metadata of AMI {instance.image_id} could not be "
                    "retrieved. Verify that ec2:DescribeImages is granted to the "
                    "scanning identity."
                )
                findings.append(report)
                continue
            image = ec2_client.image_for_instance(instance)
            if image is None:
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} runs AMI {instance.image_id}, whose "
                    "metadata could not be resolved (deregistered or not shared), so no "
                    "known emerging threat could be matched."
                )
                findings.append(report)
                continue

            hits = match_image(
                signatures, "aws", [image.name, image.description], image.owner_id
            )
            if not hits:
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} runs AMI {image.id} ({image.name}), "
                    "which no known emerging threat affects."
                )
                findings.append(report)
                continue

            # Routing is a fact about the host, whichever ports are open.
            public_route = self._public_route(instance)
            # A scan filtered to the instance does not load its security
            # groups; then exposure is unknown, not closed.
            groups_known = self._security_groups_loaded(instance)
            matches = []
            for signature, matched_name, provenance in hits:
                observed = {}
                if signature.exposure:
                    observed["public_route"] = public_route
                    if not groups_known:
                        observed["exposed_to_internet"] = None
                    else:
                        open_port = self._open_port(instance, signature.exposure)
                        observed["exposed_to_internet"] = open_port is not None
                        if open_port is not None:
                            observed["exposure_port"] = open_port
                        elif "port_not_exposed" in signature.mitigations:
                            observed["mitigations_observed"] = ["port_not_exposed"]
                matches.append(
                    to_match(
                        signature,
                        f"{image.id} ({matched_name})",
                        provenance,
                        **observed,
                    )
                )

            report.status = "FAIL"
            report.check_metadata.Severity = Severity(worst_severity(matches))
            report.raw = {
                "threats": [match.model_dump(mode="json") for match in matches]
            }
            report.status_extended = (
                f"EC2 Instance {instance.id} was launched from AMI {image.id} "
                f"({image.name}), which ships a build affected by "
                f"{describe_matches(matches)}. Prowler sees the launch image, not "
                "packages updated since: mute this finding if the host was patched "
                "in place."
            )
            findings.append(report)
        return findings

    @staticmethod
    def _security_groups_loaded(instance) -> bool:
        """Whether every security group of the instance was described in this scan."""
        loaded = {group.id for group in ec2_client.security_groups.values()}
        return (
            bool(instance.security_groups) and set(instance.security_groups) <= loaded
        )

    @staticmethod
    def _open_port(instance, exposure) -> Optional[int]:
        """The first of the threat's ports a security group of the instance opens to the internet."""
        if not instance.security_groups:
            return None
        rules = [
            rule
            for group in ec2_client.security_groups.values()
            if group.id in instance.security_groups
            for rule in group.ingress_rules
        ]
        for port in exposure.ports:
            if any(
                check_security_group(rule, exposure.protocol, [port], any_address=True)
                for rule in rules
            ):
                return port
        return None

    @staticmethod
    def _public_route(instance) -> bool:
        """A public IP in a public subnet: the route the SSH exposure checks rate critical."""
        subnet = vpc_client.vpc_subnets.get(instance.subnet_id)
        return bool(instance.public_ip) and bool(subnet and subnet.public)
