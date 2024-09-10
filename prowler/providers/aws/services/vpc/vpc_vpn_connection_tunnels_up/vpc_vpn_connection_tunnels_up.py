from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_vpn_connection_tunnels_up(Check):
    def execute(self):
        findings = []
        for vpn_arn, vpn_connection in vpc_client.vpn_connections.items():
            report = Check_Report_AWS(self.metadata())
            report.region = vpn_connection.region
            report.resource_id = vpn_connection.id
            report.resource_arn = vpn_arn
            report.resource_tags = vpn_connection.tags

            if (
                vpn_connection.tunnels[0].status != "UP"
                or vpn_connection.tunnels[1].status != "UP"
            ):
                report.status = "FAIL"
                report.status_extended = (
                    f"VPN Connection {vpn_connection.id} has at least one tunnel DOWN. "
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"VPN Connection {vpn_connection.id} has both tunnels UP. "
                )

            findings.append(report)

        return findings
