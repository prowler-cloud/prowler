from datetime import datetime, timedelta

import pytz

from prowler.lib.check.models import Check, Check_Report_IONOS
from prowler.providers.ionos.services.server.server_client import ionos_server_client


class server_volume_snapshots_exists(Check):
    def execute(self):
        findings = []

        snapshots = ionos_server_client.get_all_snapshots()

        report = Check_Report_IONOS(self.metadata(), resource={})
        report.resource_id = "volumes-snapshots"
        report.resource_name = "Volumes Snapshots"

        if not snapshots:
            report.status = "FAIL"
            report.status_extended = "Datacenter does not have any snapshots."
            findings.append(report)
            return findings

        threshold = datetime.now(pytz.UTC) - timedelta(days=2)
        recent_snapshots = [
            snapshot
            for snapshot in snapshots
            if snapshot.metadata.created_date > threshold
        ]

        if recent_snapshots:
            report.status = "PASS"
            report.status_extended = (
                f"Datacenter has {len(snapshots)} snapshot(s) configured, with "
                f"{len(recent_snapshots)} created in the last 2 days."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Datacenter has snapshots but none were created in the last 2 days."
            )

        findings.append(report)
        return findings
