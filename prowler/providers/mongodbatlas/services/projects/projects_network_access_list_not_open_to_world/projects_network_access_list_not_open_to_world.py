from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.config import ATLAS_OPEN_WORLD_CIDRS
from prowler.providers.mongodbatlas.services.projects.projects_client import (
    projects_client,
)


class projects_network_access_list_not_open_to_world(Check):
    """Check if MongoDB Atlas project network access list is not open to the world

    This class verifies that MongoDB Atlas projects don't have network access
    entries that allow unrestricted access from the internet (0.0.0.0/0 or ::/0).
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas project network access list check

        Iterates over all projects and checks if their network access lists
        contain entries that allow unrestricted access from anywhere.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each project
        """
        findings = []

        for project in projects_client.projects.values():
            report = CheckReportMongoDBAtlas(metadata=self.metadata(), resource=project)

            # Check if project has network access entries
            if not project.network_access_entries:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has no network access list entries configured, "
                    f"which may allow unrestricted access."
                )
            else:
                # Check for open world access
                open_entries = []

                for entry in project.network_access_entries:
                    # Check CIDR blocks
                    if entry.cidr_block and entry.cidr_block in ATLAS_OPEN_WORLD_CIDRS:
                        open_entries.append(f"CIDR: {entry.cidr_block}")

                    # Check IP addresses that are effectively open world
                    if entry.ip_address and entry.ip_address in ["0.0.0.0", "::"]:
                        open_entries.append(f"IP: {entry.ip_address}")

                if open_entries:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Project {project.name} has network access entries open to the world: "
                        f"{', '.join(open_entries)}. This allows unrestricted access from anywhere on the internet."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Project {project.name} has properly configured network access list "
                        f"with {len(project.network_access_entries)} restricted entries."
                    )

            findings.append(report)

        return findings
