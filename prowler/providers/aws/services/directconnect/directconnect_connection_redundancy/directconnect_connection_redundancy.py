from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directconnect.directconnect_client import (
    directconnect_client,
)


class directconnect_connection_redundancy(Check):
    def execute(self):
        findings = []
        if len(directconnect_client.connections):
            regions = {}
            for conn in directconnect_client.connections.values():
                if conn.region not in regions:
                    regions[conn.region] = {}
                    regions[conn.region]["Connections"] = 0
                    regions[conn.region]["Locations"] = set()
                regions[conn.region]["Connections"] += 1
                regions[conn.region]["Locations"].add(conn.location)

            for region, connections in regions.items():
                report = Check_Report_AWS(self.metadata())
                report.region = region
                report.resource_arn = directconnect_client._get_connection_arn_template(
                    region
                )
                report.resource_id = "unknown"
                if connections["Connections"] == 1:
                    report.status = "FAIL"
                    report.status_extended = (
                        "There is only one Direct Connect connection."
                    )
                else:  # Connection Redundancy is met.
                    if (
                        len(connections["Locations"]) == 1
                    ):  # All connections use the same location
                        report.status = "FAIL"
                        report.status_extended = f"There is only one location {next(iter(connections['Locations']))} used by all the Direct Connect connections."
                    else:  # Connection Redundancy and Location Redundancy is also met
                        report.status = "PASS"
                        report.status_extended = f"There are {connections['Connections']} Direct Connect connections across {len(connections['Locations'])} locations."

                findings.append(report)

        return findings
