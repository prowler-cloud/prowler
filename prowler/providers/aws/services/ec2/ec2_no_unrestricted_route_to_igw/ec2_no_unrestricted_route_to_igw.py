from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_no_unrestricted_route_to_igw(Check):
    def execute(self):
        findings = []

        for route_table in ec2_client.route_tables:
            report = Check_Report_AWS(self.metadata())
            report.region = route_table.region
            report.resource_id = route_table.id
            report.resource_arn = route_table.arn
            report.resource_tags = route_table.tags

            unrestricted_route = False
            for route in route_table.routes:
                if (
                    route.gateway_id
                    and route.gateway_id.startswith("igw-")
                    and route.destination_cidr_block == "0.0.0.0/0"
                ):
                    unrestricted_route = True
                    break

            if unrestricted_route:
                report.status = "FAIL"
                report.status_extended = f"Route table {route_table.id} has an unrestricted route to the Internet Gateway."
            else:
                report.status = "PASS"
                report.status_extended = f"Route table {route_table.id} does not have an unrestricted route to the Internet Gateway."

            findings.append(report)

        return findings
