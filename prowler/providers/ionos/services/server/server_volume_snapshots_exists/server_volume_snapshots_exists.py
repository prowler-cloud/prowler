from prowler.lib.check.models import Check, Check_Report_IONOS
from prowler.providers.ionos.services.server.server_client import ionos_server_client
from prowler.lib.logger import logger
from datetime import datetime, timedelta
import pytz

class server_volume_snapshots_exists(Check):
    def execute(self):
        findings = []
        
        snapshots = ionos_server_client.get_all_snapshots()
        
        report = Check_Report_IONOS(self.metadata())
        report.resource_id = "volumes-snapshots"
        report.resource_name = "Volumes Snapshots"

        if not snapshots:
            report.status = "FAIL"
            report.status_extended = "Datacenter does not have any snapshots."
            findings.append(report)
            return findings

        two_days_ago = datetime.now(pytz.UTC) - timedelta(days=2)
        
        recent_snapshots = []
        for snap in snapshots:
            creation_date = snap.metadata.created_date
            
            if creation_date > two_days_ago:
                recent_snapshots.append(snap)
        
        if recent_snapshots:
            report.status = "PASS"
            report.status_extended = f"Datacenter has {len(snapshots)} snapshot(s) configured, with {len(recent_snapshots)} created in the last 2 days."
        else:
            report.status = "FAIL" 
            report.status_extended = "Datacenter has snapshots but none were created in the last 2 days."

        findings.append(report)
        return findings
