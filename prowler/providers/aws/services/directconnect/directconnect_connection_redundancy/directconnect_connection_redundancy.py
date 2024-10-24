from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directconnect.directconnect_client import (
    directconnect_client,
)


class directconnect_connection_redundancy(Check):
    def execute(self):
        findings = []
        no_of_connections = 0
        locations = set()

        for conn in directconnect_client.connections.values():
            no_of_connections = no_of_connections + 1
            locations.add(conn.location)
            region = conn.region

        if no_of_connections > 0:
            report = Check_Report_AWS(self.metadata())
            report.region = region
            # Direct Connect Connections do not have ARNs.
            report.resource_arn = "Direct Connect Connection(s)"
            report.resource_id = "Direct Connect Connection(s)"
            if no_of_connections == 1:
                report.status = "FAIL"
                report.status_extended = (
                    f"There is only one direct connect connection in {region}."
                )
            else:  # no_of_connections > 2 #Connection Redundancy is met.
                if len(locations) == 1:  # All connections use the same location
                    report.status = "FAIL"
                    report.status_extended = f"There is only one location {next(iter(locations))} used by all the direct connect connections in {region}."
                else:  # Connection Redundancy and Location Redundancy is also met
                    report.status = "PASS"
                    report.status_extended = f"There are {no_of_connections} direct connect connections, using {len(locations)} locations in {region}."

            findings.append(report)

        return findings
