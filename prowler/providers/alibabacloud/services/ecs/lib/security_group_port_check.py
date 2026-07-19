from collections.abc import Collection

from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.lib.security_groups import (
    format_ports,
    get_publicly_exposed_tcp_ports,
)

ALL_PORTS_CHECK_ID = "ecs_securitygroup_restrict_all_ports_internet"


def execute_public_port_check(
    check: Check, ecs_client, check_ports: Collection[int], service_name: str
) -> list[CheckReportAlibabaCloud]:
    findings = []
    configured_ports = format_ports(check_ports)
    port_word = "port" if len(check_ports) == 1 else "ports"

    for security_group in ecs_client.security_groups.values():
        report = CheckReportAlibabaCloud(
            metadata=check.metadata(), resource=security_group
        )
        report.region = security_group.region
        report.resource_id = security_group.id
        report.resource_arn = security_group.arn
        report.status = "PASS"
        report.status_extended = f"Security group {security_group.name} ({security_group.id}) does not have {service_name} TCP {port_word} {configured_ports} open to the internet."

        if not security_group.ingress_rules_complete:
            report.status = "MANUAL"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) could not be fully evaluated because its ingress rules were not completely retrieved from Alibaba Cloud."
        elif ecs_client.is_failed_check(ALL_PORTS_CHECK_ID, security_group.arn) is True:
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) was not checked for {service_name} TCP {port_word} {configured_ports} because the all-ports internet exposure check already failed for this security group."
        else:
            exposed_ports = get_publicly_exposed_tcp_ports(
                security_group.ingress_rules, check_ports
            )
            if exposed_ports:
                exposed_port_word = "port" if len(exposed_ports) == 1 else "ports"
                report.status = "FAIL"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) has {service_name} TCP {exposed_port_word} {format_ports(exposed_ports)} open to the internet (0.0.0.0/0 or ::/0)."

        findings.append(report)
    return findings
