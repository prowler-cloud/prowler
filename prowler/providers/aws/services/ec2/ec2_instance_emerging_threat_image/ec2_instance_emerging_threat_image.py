from ipaddress import ip_address
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
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client

#: Inspector coverage status of an instance it is actively scanning.
INSPECTOR_SCANNING = "ACTIVE"
#: Inspector coverage scan type that reads the installed packages.
INSPECTOR_PACKAGE_SCAN = "PACKAGE"


class ec2_instance_emerging_threat_image(Check):
    """EC2 instances do not run an image that a known emerging threat affects.

    Threats are threat signatures (``prowler/lib/threats``) the scan
    configuration supplies under ``threat_signatures``. The matched threats
    travel in the finding's raw payload so Prowler Cloud can turn them into
    Exploitability issues without reading prose.

    The image proves where a host started, not what it runs now. Where Amazon
    Inspector reads the installed packages, its findings decide: an active
    finding for the threat's CVE on the instance confirms the match, and an
    instance Inspector actively scans with no such finding is reported as not
    affected, so a host patched in place clears. A match clears only when
    Inspector loaded its findings, scans the instance's packages, and its
    vulnerability database lists every CVE of the threat: a CVE too new for
    Inspector proves nothing by its absence.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        signatures = load_signatures(ec2_client.audit_config)
        if not signatures:
            return findings
        reported, scanned = self._inspector_evidence()

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
            matches, cleared = [], []
            on_host = reported.get(instance.id, set())
            for signature, matched_name, provenance in hits:
                confirmed = sorted(set(signature.cves) & on_host)
                if not confirmed and self._inspector_clears(
                    signature, instance.id, scanned
                ):
                    cleared.append(signature)
                    continue
                observed = {}
                if confirmed:
                    observed["confirmed_by"] = "inspector2"
                    observed["confirmed_cves"] = confirmed
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

            if not matches:
                ids = ", ".join(c for s in cleared for c in s.cves)
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} was launched from AMI {image.id} "
                    f"({image.name}), which carries {', '.join(s.title for s in cleared)}, "
                    f"but Amazon Inspector actively scans it and reports no {ids}: "
                    "the installed packages are not affected."
                )
                findings.append(report)
                continue

            report.status = "FAIL"
            report.check_metadata.Severity = Severity(worst_severity(matches))
            report.raw = {
                "threats": [match.model_dump(mode="json") for match in matches]
            }
            confirmed = sorted({c for m in matches for c in m.confirmed_cves})
            evidence = (
                f"Amazon Inspector reports {', '.join(confirmed)} on the instance."
                if confirmed and all(m.confirmed_by for m in matches)
                else "Prowler sees the launch image, not packages updated since: "
                "mute this finding if the host was patched in place."
            )
            report.status_extended = (
                f"EC2 Instance {instance.id} was launched from AMI {image.id} "
                f"({image.name}), which ships a build affected by "
                f"{describe_matches(matches)}. {evidence}"
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
    def _inspector_evidence() -> tuple[dict, set]:
        """What Amazon Inspector knows about the instances' installed packages.

        Returns:
            ``({instance id: CVE ids with an active finding}, {ids of instances
            whose packages Inspector actively scans})``, both empty when
            Inspector is off. Regions whose findings failed to load add neither.
        """
        reported, scanned = {}, set()
        for inspector in inspector2_client.inspectors:
            # Coverage without the findings would read as "nothing found".
            if inspector.findings is None:
                continue
            for finding in inspector.findings:
                if finding.vulnerability_id:
                    for resource_id in finding.resource_ids:
                        reported.setdefault(resource_id, set()).add(
                            finding.vulnerability_id
                        )
            for covered in inspector.coverage or []:
                if (
                    covered.resource_type == "AWS_EC2_INSTANCE"
                    and covered.scan_type == INSPECTOR_PACKAGE_SCAN
                    and covered.scan_status_code == INSPECTOR_SCANNING
                ):
                    scanned.add(covered.id)
        return reported, scanned

    @staticmethod
    def _inspector_clears(signature, instance_id: str, scanned: set) -> bool:
        """Whether Inspector's silence proves the instance is not affected."""
        return (
            bool(signature.cves)
            and instance_id in scanned
            and all(inspector2_client.vulnerability_known(c) for c in signature.cves)
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
        """A public IPv4 address in a public subnet, or a global IPv6 address in a
        subnet with an IPv6 default route to an internet gateway."""
        subnet = vpc_client.vpc_subnets.get(instance.subnet_id)
        if subnet is None:
            return False
        public_ipv4 = bool(instance.public_ip) and subnet.public
        public_ipv6 = (
            any(ip_address(address).is_global for address in instance.ipv6_addresses)
            and subnet.public_ipv6
        )
        return public_ipv4 or public_ipv6
