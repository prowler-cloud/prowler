from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_peering_routing_tables_with_least_privilege(Check):
    def execute(self):
        findings = []
        for peer in vpc_client.vpc_peering_connections:
            report = Check_Report_AWS(self.metadata())
            report.region = peer.region
            comply = True
            # Check each cidr in the peering route table
            for route_table in peer.route_tables:
                for cidr in route_table.destination_cidrs:
                    if (
                        cidr == "0.0.0.0/0"
                        or cidr == peer.requester_cidr
                        or cidr == peer.accepter_cidr
                    ):  # Check if cidr does not accept whole requester/accepter VPC CIDR
                        comply = False
            if not comply:
                report.status = "FAIL"
                report.status_extended = f"VPC Peering Connection {peer.id} does not comply with least privilege access since it accepts whole VPCs CIDR in its route tables."
                report.resource_id = peer.id
            else:
                report.status = "PASS"
                report.status_extended = f"VPC Peering Connection {peer.id} comply with least privilege access."
                report.resource_id = peer.id
            findings.append(report)

        return findings
